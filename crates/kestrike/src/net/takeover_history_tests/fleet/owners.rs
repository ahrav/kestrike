//! Each per-shard owner incarnation reads its role with `host::survey` and runs `host::recover` through a
//! `host::Fencer` over its host's `Reserving` device double on the shard's media. The fencer and every host's device
//! double of one volume share the cell's reservation table (`World::reservation`), so a fencer's commands and a
//! tenure's Reports read one table. `host::serve::start_up_with_nonce`, the steps of `start_up` under the boot nonce
//! the fleet scripts from the cell's count of tenures served, starts the tenure `recover` returns, and each of its
//! owner turns in the round loop is one `host::serve::turn_up` until the bring-up reads `Live` or ends short of it.
//! A blank volume's format ID is the one `turn_up` draws from the operating system. In a host scenario a rising
//! tenure joins the fleet's bring-ups in progress ([`Rise`]) and the host loop goes on with its queued work, so a
//! second recovery of the same host starts while the first loads and the round loop steps both loads in each round.
//! Each bring-up's recovery is accounted once its client session is active.

use std::cell::{Cell as Slot, RefCell};
use std::rc::Rc;

use crate::failover::admission::AdmissionError;
use crate::failover::attachments::ControlPlane;
use crate::failover::evidence::Pair;
use crate::failover::fresh::{LocalRecords, Refusals};
use crate::failover::poll::Holder;
use crate::failover::record::LocalRecord;
use crate::failover::records::{Host, Record, ShardRecord, VolumeRecord, VolumeState};
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
    cell: (&Cell, Member, Pair),
    round: u64,
    grounds: &'w Grounds,
    client: &mut Client<S, L>,
    sources: (&mut R, &mut K, &mut Refusals),
) -> Incarnation<'w>
where
    S: Store,
    L: WatermarkLog,
    R: LocalSource + LocalRecords,
    K: ControlPlane,
{
    incarnate_read(cell, round, grounds, client, sources).0
}

/// [`incarnate`], with the tenure its role read named for the host as owner: the tenure of the shard record the
/// read returned when the role is `Role::Restart` or `Role::Fresh`, and none for a waiting or retired role and for
/// a role read that failed.
pub(super) fn incarnate_read<'w, S, L, R, K>(
    (cell, of, pair): (&Cell, Member, Pair),
    round: u64,
    grounds: &'w Grounds,
    client: &mut Client<S, L>,
    (local, plane, refusals): (&mut R, &mut K, &mut Refusals),
) -> (Incarnation<'w>, Option<Tenure>)
where
    S: Store,
    L: WatermarkLog,
    R: LocalSource + LocalRecords,
    K: ControlPlane,
{
    let volume = cell.placement.volume;
    let holder = crate::failover::takeover::tests::holder_on(volume, of.host, of.instance);
    let shard = cell.placement.shard;
    let (role, volume, record) = match host::survey(client, shard, &holder) {
        Ok(surveyed) => surveyed,
        Err(error) => return (Incarnation::Unread(error), None),
    };
    let named = matches!(role, Role::Restart | Role::Fresh).then(|| tenure_at(Target::of(&record)));
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
    let incarnation = match recovered {
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
    };
    (incarnation, named)
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
/// `host::stand_by` over `client` and `local`, whose `period` passes at each call and sets the stop flag on its
/// second. The wait publishes its status to a cell of this period that no agent takes: `Fleet::statuses` builds the
/// status the host's agent turns over. The period reads `witness` at the time it carries, and the takeover it starts
/// runs through a fencer over the host's device double on the arena and clock of `grounds`. Its connect records
/// whether the shard record already names `of`'s host owner with no standby, read from `store` with no request, and,
/// with `acked`, whether the period's own last write of the shard record had an acknowledged `Committed` reply;
/// `client` then writes through an [`AckLogged`] store over that log, and a period with no witness passes `None`,
/// under which any device call fails the assertion. Once `host::stand_by` returns the period asserts that every
/// device call followed the committed takeover (CAS-BEFORE-DEVICE, [`follows`]) and that no takeover unwound. Under
/// `early`, the fencer starts the device before the period runs and before any takeover write. With a witness that
/// early call fails the assertion. With no witness the wait returns the device with `Exit::Fault` before its first
/// period, and the period skips the assertion for that exit.
pub(super) fn stand_by<'w, S, L>(
    (cell, of, pair): (&Cell, Member, Pair),
    (round, store): (u64, &crate::storage::store::sim::Shared),
    grounds: &'w Grounds,
    (client, local): (&mut Client<S, L>, &Stored),
    (witness, early, acked): (
        Option<(crate::failover::detect::host::Revalidated, u64)>,
        bool,
        Option<&Acked>,
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
    let gate = HostGate::qualified();
    let (store, host) = (store.clone(), of.host);
    // The device double is made at the connect, the takeover's first device call, so a period that starts no
    // takeover makes none. The record a device call met before the committed takeover is judged once
    // `host::stand_by` returns, outside its unwind boundary.
    let connected: RefCell<Option<SimControl>> = RefCell::new(None);
    // The record the connect met: its owner and standby, or `None` for an absent or undecodable record or one of
    // another shard, each of which the assertion after `host::stand_by` fails.
    type Met = Option<(Host, Option<Host>)>;
    let early_call: Slot<Option<Met>> = Slot::new(None);
    let connect = || {
        let met = {
            let store = store.0.borrow();
            (store.current(&crate::storage::store::Key::Shard(shard)))
                .and_then(|item| ShardRecord::decode(&item.value).ok())
                .filter(|record| record.shard == shard)
                .map(|record| (record.owner, record.standby))
        };
        // A period with no write log takes no witness, so a device call it makes follows no takeover of its own.
        let own = acked.is_some_and(|acked| acked.last_acknowledged(shard));
        if !follows(met, host, own) {
            early_call.set(Some(met));
        }
        let (disk, control) = device(cell, pair);
        grounds.fencer.drive(&control);
        *connected.borrow_mut() = Some(control);
        Ok((disk, pair))
    };
    let mut fencer =
        host::fencer::Fencer::new(&gate, connect, limits(), &grounds.buffers, &grounds.fencer);
    if early {
        let _ = crate::failover::takeover::Device::start(&mut fencer);
    }
    let stop = std::sync::atomic::AtomicBool::new(false);
    let periods = Slot::new(0_u32);
    let period = |_| {
        periods.set(periods.get() + 1);
        if periods.get() > 1 {
            stop.store(true, std::sync::atomic::Ordering::Release);
        }
        true
    };
    let waiting = witness.is_none();
    let read_at = witness.as_ref().map_or(round * ROUND_US, |(_, at)| *at);
    let status = host::link::StatusCell::default();
    let mut witness = witness.map(|(witness, _)| witness);
    let signals = host::Signals {
        stop: &stop,
        period,
        nominations: || witness.take(),
        now: || read_at,
        status: &status,
        pid: 0,
        // The fleet's detector window is one round.
        window_us: ROUND_US,
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
    // A wait with no witness whose fencer already held a device returns it with `Exit::Fault` before any period, the
    // production refusal of a waiting phase that holds a device; the caller lists that exit.
    let refused =
        early && waiting && matches!(&stood, Err(ended) if matches!(ended.exit, Exit::Fault(_)));
    if !refused {
        assert_eq!(
            early_call.get(),
            None,
            "the first device call follows its own acknowledged takeover write"
        );
    }
    let control = connected.into_inner();
    match stood {
        Ok(tenure) => Stood::Tenure(tenure, control.expect("a takeover's device"), now),
        Err(ended) => {
            let host::recover::Ended {
                exit,
                device,
                refusal,
            } = *ended;
            if let host::fencer::Release::Outstanding(table) = device {
                stop_table(table, control.as_ref().expect("a connected device"));
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

/// A bring-up in progress in a host scenario: the tenure `tenure` of cell `at` rising since round `since` from
/// `source`, whose client session the fleet opens once the bring-up reads `Live` (`opened`), and what the host loop
/// does once the session is active (`then`). A rise whose cell no longer holds its tenure ends with no recovery.
pub(super) struct Rise {
    pub(super) at: usize,
    pub(super) tenure: Tenure,
    /// The member whose process started the rise: the cell's holder when the rise was queued.
    pub(super) member: usize,
    /// The round the rise's present phase started: its bring-up, then its client session.
    pub(super) since: u64,
    pub(super) source: Source,
    pub(super) opened: bool,
    /// The round after the turn in which the bootstrap first read ended ([`Fleet::note_rises`]).
    pub(super) booted_at: Option<u64>,
    /// The round after the turn in which the opened session first read active ([`Fleet::note_rises`]).
    pub(super) active_at: Option<u64>,
    pub(super) then: Then,
}

/// What the host loop does once a rise's client session is active, or once the rise ended with no tenure.
#[derive(Debug, Clone, Copy)]
pub(super) enum Then {
    /// `member`'s takeover of a shard lost at round `lost_at`; `lineage` when the next incarnation after its refused
    /// takeover restarted through the lineage arm.
    TakeOver {
        member: usize,
        lost_at: u64,
        lineage: bool,
    },
    /// `member`'s restart, whose recovery counts its rounds from `lost_at` and arms the loss plants when
    /// `after_loss`; `lineage` when it restarted through the lineage arm, `from` the record's attempt count read just
    /// before it, and `returned` when it is a returning host's restart.
    Restart {
        member: usize,
        lost_at: u64,
        after_loss: bool,
        lineage: bool,
        from: u32,
        returned: bool,
    },
    /// The owner's fresh activation on a replacement volume, after the loss at round `lost_at`.
    Fresh { lost_at: u64 },
}

impl Fleet<'_> {
    /// Starts the tenure `recover` returned through `host::serve::start_up` and puts it into `live[at]` with its
    /// bring-up rising, emitting its `Fenced` step. Returns the tenure, or `None` when the bring-up ended before the
    /// owner's first poll, which is the cell's blocker.
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
    ) -> Option<Tenure> {
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
                return None;
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
        live[at] = Some(serving);
        Some(tenure)
    }

    /// Joins `tenure`'s bring-up on cell `at`, which [`Fleet::rise`] started, to the bring-ups in progress; `None`
    /// runs `then` at once with no tenure, as a bring-up that ended before its first poll.
    pub(super) fn queue_rise(
        &mut self,
        live: &mut Live<'_>,
        at: usize,
        (tenure, source): (Option<Tenure>, Source),
        then: Then,
    ) -> Result<(), Stopped> {
        let Some(tenure) = tenure else {
            return self.risen(live, at, None, then, self.round);
        };
        let member = self.cells[at].holder;
        // Two takeover loads of one host: each rise names the member that started it, so a cell another member
        // has since taken, and a restart's load, lend no overlap.
        let takes = |then: &Then| matches!(then, Then::TakeOver { .. });
        let beside = takes(&then)
            && (self.rises.iter())
                .any(|rise| rise.member == member && rise.at != at && takes(&rise.then));
        self.log.overlapped += u32::from(beside);
        self.rises.push(Rise {
            at,
            tenure,
            member,
            since: self.round,
            source,
            opened: false,
            booted_at: None,
            active_at: None,
            then,
        });
        Ok(())
    }

    /// Stamps each rise whose present phase has ended with the present round, once: a bootstrap that left its
    /// initializing states, and an opened client session that reads active. `Fleet::turn` calls it after each
    /// round, so a phase that ends while the host loop sweeps another recovery keeps the round it ended in.
    pub(super) fn note_rises(&mut self, live: &Live<'_>) {
        for rise in &mut self.rises {
            let held = live[rise.at].as_ref();
            let Some(serving) = held.filter(|serving| serving.tenure == rise.tenure) else {
                continue;
            };
            if !rise.opened {
                let booted = serving.rising.is_none() && !serving.owner.readiness().initializing();
                if booted && rise.booted_at.is_none() {
                    rise.booted_at = Some(self.round);
                }
            } else if rise.active_at.is_none()
                && serving.client.state() == crate::net::client::SessionState::Active
            {
                rise.active_at = Some(self.round);
            }
        }
    }

    /// The cells whose takeover's warm load is in progress, in the order the loads started.
    pub(super) fn takeover_loads(&self) -> impl Iterator<Item = usize> + '_ {
        (self.rises.iter())
            .filter(|rise| matches!(rise.then, Then::TakeOver { .. }))
            .map(|rise| rise.at)
    }

    /// Whether a bring-up of cell `at` is in progress.
    pub(super) fn rising_at(&self, at: usize) -> bool {
        self.rises.iter().any(|rise| rise.at == at)
    }

    /// Advances each bring-up in progress, in the order they started: one whose bootstrap left its initializing
    /// states activates its load and opens its client session (`Fleet::opened`), and one whose session is active, or
    /// that ended short, runs its `then`. A rise whose cell no longer holds its tenure (a crash or a takeover dropped
    /// it) runs its `then` with no tenure.
    ///
    /// # Errors
    ///
    /// `Stopped::Stalled` naming the shard and the phase when a phase is still pending `Fleet::wait` rounds after it
    /// started, or ended later than that, the bound of a synchronous bring-up (`Fleet::turns_while`); a phase is
    /// judged by the round it ended in, however late this look. Also whatever a `then`'s sweep stops with.
    pub(super) fn step_rises(&mut self, live: &mut Live<'_>) -> Result<(), Stopped> {
        let mut index = 0;
        while index < self.rises.len() {
            let Rise {
                at,
                tenure,
                since,
                source,
                opened,
                booted_at,
                active_at,
                then,
                ..
            } = self.rises[index];
            let held = live[at].as_ref().filter(|serving| serving.tenure == tenure);
            let Some(serving) = held else {
                self.rises.remove(index);
                self.risen(live, at, None, then, self.round)?;
                continue;
            };
            let wait = u64::from(self.wait);
            let late = self.round - since >= wait;
            if !opened {
                if serving.rising.is_some() || serving.owner.readiness().initializing() {
                    if late {
                        return Err(self.stalled(Some(at), "the bootstrap"));
                    }
                    index += 1;
                    continue;
                }
                if booted_at.unwrap_or(self.round) - since > wait {
                    return Err(self.stalled(Some(at), "the bootstrap"));
                }
                if !self.opened(live, at, source) {
                    self.rises.remove(index);
                    self.risen(live, at, None, then, self.round)?;
                    continue;
                }
                (self.rises[index].opened, self.rises[index].since) = (true, self.round);
                index += 1;
                continue;
            }
            if serving.client.state() != crate::net::client::SessionState::Active {
                if late {
                    return Err(self.stalled(Some(at), "the client session"));
                }
                index += 1;
                continue;
            }
            // The recovery ends in the round its session became active, which a sweep ahead of it leaves behind.
            let active = active_at.unwrap_or(self.round);
            if active - since > wait {
                return Err(self.stalled(Some(at), "the client session"));
            }
            self.rises.remove(index);
            self.risen(live, at, Some(tenure), then, active)?;
        }
        Ok(())
    }

    /// What the host loop does once cell `at`'s bring-up ended: with the tenure whose session opened, its recovery's
    /// sweep and accounting, the recovery's rounds ending at `active`, the round its session became active; with
    /// none, the hosts' reread of the record alone. The zone's hosts reread the record once the bring-up ended, as
    /// they did when the host loop waited for it.
    fn risen(
        &mut self,
        live: &mut Live<'_>,
        at: usize,
        tenure: Option<Tenure>,
        then: Then,
        active: u64,
    ) -> Result<(), Stopped> {
        self.reread_hosts(at);
        let Some(tenure) = tenure else {
            return Ok(());
        };
        match then {
            Then::TakeOver {
                member,
                lost_at,
                lineage,
            } => {
                if self.config.planted_at(super::Plant::TwinStart, at) {
                    let attempts = u32::try_from(tenure.a / 2 - 1).expect("an attempt count");
                    let session = crate::storage::session_at(tenure.g, attempts);
                    assert_eq!(super::tenure_of(session.get()), tenure);
                    let _twin = crate::storage::ServingAuthority::fixture_under(session);
                    let owner = self.cells[at].placement.owner;
                    let other = (0..self.topology.members.len())
                        .find(|&other| other != member && other != owner)
                        .expect("a third host");
                    (self.activations).push((at, tenure, self.topology.members[other].host));
                    self.log.twin_started += 1;
                    self.planted = true;
                }
                if lineage {
                    let shard = self.cells[at].placement.shard.get();
                    let host = self.topology.members[member].host.get();
                    let round = self.round - self.host_start;
                    self.volumes.arm.push((shard, host, round));
                }
                let rounds = active - lost_at;
                self.recovered(live, at, tenure, rounds, (true, true))
            }
            Then::Restart {
                member,
                lost_at,
                after_loss,
                lineage,
                from,
                returned,
            } => {
                // The guard reads the owner's present state, as `failover::zone_loop::plan` does: a member that
                // serves holds at no device step.
                self.cells[at].device_holds.remove(&member);
                let shard = self.cells[at].placement.shard.get();
                let host = self.topology.members[member].host.get();
                if lineage {
                    let round = self.round - self.host_start;
                    self.volumes.arm.push((shard, host, round));
                }
                self.unhold(at);
                let rounds = active - lost_at;
                self.recovered(live, at, tenure, rounds, (after_loss, after_loss))?;
                if returned {
                    self.restart_served(live, at, member, (tenure, from));
                }
                Ok(())
            }
            Then::Fresh { lost_at } => {
                self.volumes.cold.push(self.cells[at].placement.shard.get());
                self.unhold(at);
                self.recovered(live, at, tenure, active - lost_at, (true, true))
            }
        }
    }
}

/// One extended Report issued as `pair` through a fencer over the host's device double on `cell`, on the arena and
/// clock of `grounds`. The fencer's table ends with no command before the call returns.
pub(super) fn report_as(cell: &Cell, pair: Pair, grounds: &Grounds) {
    use crate::failover::restart::Device;
    let (disk, control) = device(cell, pair);
    grounds.fencer.drive(&control);
    let gate = HostGate::qualified();
    let mut fencer = host::fencer::Fencer::new(
        &gate,
        move || Ok((disk, pair)),
        limits(),
        &grounds.buffers,
        &grounds.fencer,
    );
    let reported = fencer.start().is_ok() && fencer.ready().is_ok() && fencer.report().is_ok();
    grounds.fencer.release();
    assert!(reported, "the device double completes a Report");
    if let host::fencer::Release::Outstanding(table) = fencer.release() {
        stop_table(table, &control);
    }
}

/// [`report_as`] on the arena and clock the standby waits' view periods take.
pub(super) fn report_in_wait(cell: &Cell, pair: Pair) {
    WAITS.with(|grounds| report_as(cell, pair, grounds));
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

/// Whether a role read that returned `volume` and `shard` names `host` standby, by the rule of `host::survey`: the
/// volume is the shard's active volume, and the shard record names another owner and `host` standby. A volume in
/// another state, or one that contradicts the shard record, makes the role retired or unnamed.
fn reads_standby(host: Host, volume: &VolumeRecord, shard: &ShardRecord) -> bool {
    let active = crate::failover::flip::volume_state(shard, volume) == Ok(VolumeState::Active);
    active && shard.owner != host && shard.standby == Some(host)
}

/// The first value a read of each key returned, by key.
pub(super) type Returned =
    std::collections::BTreeMap<crate::storage::store::Key, crate::storage::store::Item>;

/// Whether a device call that met `met`, the shard record's owner and standby (`None` for no decodable record of the
/// shard), follows the committed takeover of `host`: the record names `host` owner with no standby, and `own`, the
/// takeover period's last write of the shard record had an acknowledged `Committed` reply. A takeover write whose
/// reply was unknown leaves the record naming `host` when it committed, and no device call may follow it. `own`
/// reads the store's reply alone: a `Committed` reply that the client then refuses, at its watermark log, reads as
/// acknowledged here, and the client's own refusal ends the takeover before any device call.
pub(super) fn follows(met: Option<(Host, Option<Host>)>, host: Host, own: bool) -> bool {
    met == Some((host, None)) && own
}

/// The shard-record writes a takeover period's store client made, each with whether its reply was an acknowledged
/// `Committed`, in order.
#[derive(Default)]
pub(crate) struct Acked(RefCell<Vec<(crate::net::ownership::Shard, bool)>>);

impl Acked {
    /// The shard-record writes the period issued, whatever their replies.
    pub(super) fn writes(&self) -> usize {
        self.0.borrow().len()
    }

    /// Whether the last write of `shard`'s record had an acknowledged `Committed` reply.
    pub(super) fn last_acknowledged(&self, shard: crate::net::ownership::Shard) -> bool {
        let writes = self.0.borrow();
        let last = writes.iter().rev().find(|(of, _)| *of == shard);
        last.is_some_and(|(_, acknowledged)| *acknowledged)
    }
}

/// A store that logs each shard-record write's reply into an [`Acked`] log, which a takeover period's client makes
/// its compare-and-swap through.
pub(crate) struct AckLogged<'a, S> {
    pub(crate) inner: S,
    pub(crate) log: &'a Acked,
}

impl<S: Store> Store for AckLogged<'_, S> {
    fn read(
        &mut self,
        key: &crate::storage::store::Key,
    ) -> Result<Option<crate::storage::store::Item>, crate::storage::store::Unavailable> {
        self.inner.read(key)
    }

    fn write(
        &mut self,
        key: &crate::storage::store::Key,
        write: &crate::storage::store::Write,
    ) -> crate::storage::store::Outcome {
        let outcome = self.inner.write(key, write);
        if let crate::storage::store::Key::Shard(shard) = key {
            let committed = matches!(outcome, crate::storage::store::Outcome::Committed(_));
            self.log.0.borrow_mut().push((*shard, committed));
        }
        outcome
    }

    fn namespace(&self) -> crate::failover::records::Namespace {
        self.inner.namespace()
    }
}

/// A store that keeps the first value a read of each key returned. A standby wait's client reads through it above
/// the fault layer, so it holds the replies that client received, and a period's role read is its first read of each
/// record: a later read of the same key in the period, such as `enroll_standby`'s, leaves the kept value as it is.
pub(crate) struct Returning<S> {
    pub(crate) inner: S,
    pub(crate) returned: Rc<RefCell<Returned>>,
}

impl<S: Store> Store for Returning<S> {
    fn read(
        &mut self,
        key: &crate::storage::store::Key,
    ) -> Result<Option<crate::storage::store::Item>, crate::storage::store::Unavailable> {
        let read = self.inner.read(key);
        if let Ok(Some(item)) = &read {
            let mut returned = self.returned.borrow_mut();
            returned.entry(*key).or_insert_with(|| item.clone());
        }
        read
    }

    fn write(
        &mut self,
        key: &crate::storage::store::Key,
        write: &crate::storage::store::Write,
    ) -> crate::storage::store::Outcome {
        self.inner.write(key, write)
    }

    fn namespace(&self) -> crate::failover::records::Namespace {
        self.inner.namespace()
    }
}

/// A store that lists the key of each read whose returned value fails the store client's decode for that key: the
/// record's own decode, and for a volume record or a shard record the key the decoded record names. A read of any
/// other key kind is listed whatever it returns, since the layer holds no decode for it.
pub(crate) struct Decoding<S> {
    pub(crate) inner: S,
    pub(crate) failed: Rc<RefCell<Vec<crate::storage::store::Key>>>,
}

impl<S: Store> Store for Decoding<S> {
    fn read(
        &mut self,
        key: &crate::storage::store::Key,
    ) -> Result<Option<crate::storage::store::Item>, crate::storage::store::Unavailable> {
        use crate::failover::records::CoveragePage;
        use crate::storage::store::Key;
        let read = self.inner.read(key);
        if let Ok(Some(item)) = &read {
            let named = match key {
                Key::Volume(_) => (VolumeRecord::decode(&item.value).ok())
                    .map(|record| Key::Volume(record.volume)),
                Key::Shard(_) => {
                    (ShardRecord::decode(&item.value).ok()).map(|record| Key::Shard(record.shard))
                }
                Key::Page(..) => CoveragePage::decode(&item.value).ok().map(|_| *key),
                _ => None,
            };
            if named != Some(*key) {
                self.failed.borrow_mut().push(*key);
            }
        }
        read
    }

    fn write(
        &mut self,
        key: &crate::storage::store::Key,
        write: &crate::storage::store::Write,
    ) -> crate::storage::store::Outcome {
        self.inner.write(key, write)
    }

    fn namespace(&self) -> crate::failover::records::Namespace {
        self.inner.namespace()
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

/// `WaitCounts` holds the reads and the writes of one view period of a standby wait, by key.
#[derive(Default)]
pub(crate) struct WaitCounts {
    pub(crate) keys: super::DutyCounts,
    /// The first value the period's client received from a read of each key ([`Returning`]).
    pub(crate) returned: Rc<RefCell<Returned>>,
}

impl WaitCounts {
    /// The period's reads and writes over every key.
    fn tally(&self) -> (u64, u64) {
        let counts = self.keys.borrow();
        counts
            .values()
            .fold((0, 0), |(reads, writes), (read, written)| {
                (reads + read, writes + written)
            })
    }

    /// The period's requests on `key`.
    pub(crate) fn on(&self, key: &crate::storage::store::Key) -> u64 {
        let counts = self.keys.borrow();
        counts.get(key).map_or(0, |(reads, writes)| reads + writes)
    }
}

thread_local! {
    /// The arena and fencer clock a standby's view period with no witness takes: such a period starts no takeover
    /// and nothing attaches over them. Its fencer connects only under `Plant::WaitDevice`, which starts the device
    /// over these grounds before each period of the planted wait.
    static WAITS: &'static Grounds = Box::leak(Box::new(Grounds::over(crate::storage::warm_sim::storage(1))));
}

impl Fleet<'_> {
    /// One view period of every standby wait: each running host the shard record names standby of a shard it does
    /// not hold, and whose nomination queue holds no witness for the shard's active volume, runs `host::stand_by`
    /// for one period with no witness, over its own store client, whose requests the
    /// client counts by key for that period ([`WaitCounts`]). `Cell::excuse` adds the period's requests on the
    /// shard's records to `Cell::waited`, by key. Each
    /// period's reads and writes join the shard's wait tally (`Cell::waits`), and a period that ended other than
    /// `Exit::Stopped` is listed (`Cell::wait_exits`); the untouched-shard rule bounds every period at two reads and
    /// no write. Under [`super::Plant::StandbyExtraRead`] the standby of the shard at the index reads the
    /// shard record once more in each period. A waiting process whose host the record names owner while another
    /// member holds the cell, the target of a planned handoff, keeps its period too: that period reads the restart
    /// role and ends `Rerun(RoleChanged)`, the host log lists the role change, and the process's next incarnation is
    /// queued ([`Fleet::queue_rerun`]), as it is after a period that ended `Rerun(Records)` under such a record.
    pub(super) fn standby_waits(&mut self) {
        for at in 0..self.cells.len() {
            let record = self.record_now(at);
            let runs = |member: usize| {
                self.cells[at].holder != member
                    && self.hosts[member].up == super::hosts::Up::Running
            };
            let standby = (record.standby)
                .and_then(|standby| self.member_of(standby))
                .filter(|&member| runs(member));
            // A waiting process whose host the record names owner at a tenure the cell's holder does not hold, the
            // planned handoff's target, keeps its period, which reads the restart role.
            let unwaited = self.config.planted_at(super::Plant::TargetUnwaited, at);
            self.planted |= unwaited && self.cells[at].waiting.is_some() && standby.is_none();
            let target = (self.cells[at].waiting)
                .map(|(of, ..)| of)
                .filter(|&of| self.topology.members[of].host == record.owner && runs(of))
                .filter(|_| !unwaited);
            let waiter = standby.or(target);
            // A process that the record stopped naming standby, that holds the shard, or whose host stopped publishes
            // no `Standby` for the shard: its wait reads another role, or no wait runs.
            if self.cells[at]
                .waiting
                .is_some_and(|(of, ..)| Some(of) != waiter)
            {
                self.cells[at].waiting = None;
            }
            let Some(member) = waiter else {
                continue;
            };
            let cell = &self.cells[at];
            // A process whose inbox holds a nomination for the shard's active volume runs its period with the
            // witness, in `Fleet::take_over`.
            let inbox = (member, record.active);
            if (self.nominated.iter()).any(|(of, on, ..)| (*of, *on) == inbox) {
                continue;
            }
            let Some((pair, local)) = cell.local_of(member) else {
                continue;
            };
            let of = self.topology.members[member];
            let counts = WaitCounts::default();
            let mut client = self.standby_client(member, &counts);
            if self.config.planted_at(super::Plant::StandbyExtraRead, at) {
                self.planted = true;
                let own = crate::storage::store::Key::Shard(cell.placement.shard);
                let key = self.standby_extra.unwrap_or(own);
                let _ = client.read::<crate::failover::records::ShardRecord>(key);
                counts.returned.borrow_mut().clear();
            }
            let refused = |_| Err(AdmissionError::AttemptConsumed);
            let early = self.config.planted_at(super::Plant::WaitDevice, at);
            self.planted |= early;
            let stood = WAITS.with(|grounds| {
                stand_by(
                    (cell, of, pair),
                    (self.round, &self.store),
                    grounds,
                    (&mut client, &local),
                    (None, early, None),
                    refused,
                )
            });
            drop(client);
            let Stood::Ended(exit, _) = stood else {
                panic!("a view period with no witness acquired a tenure");
            };
            let (reads, writes) = counts.tally();
            let after = self.record_now(at);
            let cell = &mut self.cells[at];
            cell.excuse(&counts);
            cell.waits.push((reads, writes));
            if exit != Exit::Stopped {
                cell.wait_exits.push(format!("{exit:?}"));
                cell.waiting = None;
                let rerun = matches!(
                    exit,
                    Exit::Rerun(crate::host::Rerun::RoleChanged | crate::host::Rerun::Records)
                );
                if rerun && after.owner == of.host && !self.refused.contains_key(&(at, member)) {
                    if exit == Exit::Rerun(crate::host::Rerun::RoleChanged) {
                        let since = self.round - self.host_start;
                        let shard = cell.placement.shard.get();
                        self.log.role_changes.push((since, shard, of.host.get()));
                    }
                    self.queue_rerun(at, member, &exit, false);
                    self.rerun_starts.insert((at, member), self.round);
                }
            } else {
                self.publish_read(at, member, &counts.returned);
            }
        }
    }

    /// One view period of the wait of each attached host that the shard's volume record does not enroll: a running
    /// host of the shard's zone whose live attach the record binds to its own instance and whose instance the zone
    /// double lists attached, so its owner process runs for the volume. The period is `host::stand_by` with no
    /// witness over the host's enrollment client (`Fleet::enroll_client`), whose requests the untouched-shard rule
    /// counts as the reconcilers' and enrollments'. Its unnamed or standby arm calls `enroll_standby` when the role
    /// read's records admit the host, and `persist` makes the host's local record durable before that call's
    /// enrollment write. Once the volume record enrolls the pair the persisted record carries, the cell keeps it as
    /// the host's local record. In an enrollment crash cell the period's enrollment write, the one write a wait
    /// issues, ends as the cell names when the cell is the repaired one and the host the one the loop's status names
    /// for its need.
    pub(super) fn unnamed_waits(&mut self) {
        use super::hosts::{Scenario, Up};
        use super::reconcile::{Call, Status};
        let mut due = Vec::new();
        for at in 0..self.cells.len() {
            let placement = self.cells[at].placement;
            let volume = self.volume_now(at);
            let unenrolled = (volume.live_hosts())
                .filter(|&host| volume.enrolled(host).is_none())
                .filter_map(|host| {
                    let member = self.member_of(host)?;
                    let of = self.topology.members[member];
                    let seq = volume.live(host)?;
                    let bound =
                        volume.event(seq).and_then(|entry| entry.instance) == Some(of.instance);
                    let running = self.hosts[member].up == Up::Running;
                    (bound && running && of.zone == placement.zone).then_some((member, of.instance))
                });
            let unenrolled: Vec<_> = unenrolled.collect();
            if unenrolled.is_empty() {
                continue;
            }
            let double = self
                .double(placement.zone)
                .expect("a repairing fleet's zone double");
            let listed = ControlPlane::attachments(double, &placement.volume).unwrap_or_default();
            for (member, instance) in unenrolled {
                if listed.iter().any(|attached| attached == instance.as_str()) {
                    due.push((at, member));
                }
            }
        }
        for (at, member) in due {
            let of = self.topology.members[member];
            let placement = self.cells[at].placement;
            let aimed = || {
                let (repaired, need) = self.repaired()?;
                let named = (self.cells[at].planned.iter()).any(|(host, _)| *host == of.host);
                (repaired == at && named).then_some(need)
            };
            let cell = match self.config.scenario {
                Scenario::Crash(cell)
                    if cell.call == Call::Enroll
                        && self.recon.crashed.is_empty()
                        && self.log.host_losses > 0
                        && self.reconcilers[0].status == Status::Running =>
                {
                    aimed().map(|need| (cell, need))
                }
                _ => None,
            };
            if let Some((_, need)) = cell {
                self.recon.crash_aim = Some((placement.shard.get(), need));
            }
            let cell = cell.map(|(cell, _)| cell);
            let key = crate::storage::store::Key::Volume(placement.volume);
            let before = self.store.0.borrow().commit_count(&key);
            // The cell's arm stands behind every write arm an episode queued for the member, under its own ticket.
            let armed = cell.map(|cell| {
                let mut faults = self.faults.store.borrow_mut();
                faults.arm_write(member as u32, cell.ending.arm())
            });
            // A host with no local record reads `Absent` until its enrollment's `persist`; the pair is the fencer's
            // issuing pair, which a period with no witness never connects with.
            let held = self.cells[at].local_of(member);
            let (pair, local) = match held {
                Some(held) => held,
                None => (self.cells[at].pair, Stored(Err(Local::Absent))),
            };
            let failed = Rc::new(RefCell::new(Vec::new()));
            let mut client = self.enroll_client(member, &failed);
            let mut persisted = None;
            let persist = |key| Ok(persisted.insert(self.local_record(at, member, key)).clone());
            let stood = WAITS.with(|grounds| {
                stand_by(
                    (&self.cells[at], of, pair),
                    (self.round, &self.store),
                    grounds,
                    (&mut client, &local),
                    (None, false, None),
                    persist,
                )
            });
            assert!(
                !client.withdrawn(),
                "host {member}'s enrollment client of s{at} was withdrawn"
            );
            drop(client);
            let Stood::Ended(..) = stood else {
                panic!("an unnamed host's view period with no witness acquired a tenure");
            };
            assert!(
                failed.borrow().is_empty(),
                "host {member}'s view period of s{at} read values the layer cannot decode under their keys: {:?}",
                failed.borrow()
            );
            if let (Some(cell), Some(ticket)) = (cell, armed) {
                // The period's enrollment took the cell's arm when its ticket is gone from the queue. An arm it left
                // is withdrawn by that ticket, and an episode's arms for the member stay queued.
                let untaken = (self.faults.store.borrow_mut()).withdraw(member as u32, ticket);
                if !untaken {
                    let after = self.store.0.borrow().commit_count(&key);
                    self.recon.crashed.push(cell.name());
                    self.recon.crash_writes.push((before, after));
                    self.drop_loop(0);
                }
            }
            // The host persists its local record before the volume write. Once the volume record enrolls the pair
            // that record carries, after an acknowledged write or one whose unknown reply committed, the cell keeps
            // it; an uncommitted write leaves the host unenrolled for a later period.
            let pair = self.volume_now(at).enrolled(of.host);
            if let (Some(local), Some(pair)) = (persisted, pair)
                && local.pair() == pair
            {
                self.cells[at].enrolled(member, pair, Stored(Ok(local)));
            }
        }
    }

    /// Publishes or ends `member`'s `Standby` status for cell `at` from the two records a period's role read
    /// returned to its client, the volume record first and then the shard record: the member waits as the standby
    /// they name, or reads another role and publishes no `Standby`. A period whose shard read returned no value
    /// leaves the status as it is. Both a view period of the waits and a takeover's period with its witness publish
    /// through it.
    pub(super) fn publish_read(&mut self, at: usize, member: usize, returned: &RefCell<Returned>) {
        let placement = self.cells[at].placement;
        let read = {
            let mut returned = returned.borrow_mut();
            let volume = returned.remove(&crate::storage::store::Key::Volume(placement.volume));
            let shard = returned.remove(&crate::storage::store::Key::Shard(placement.shard));
            volume.zip(shard)
        };
        let Some((volume, shard)) = read else {
            return;
        };
        let host = self.topology.members[member].host;
        let volume = VolumeRecord::decode(&volume.value).expect("a stored volume record");
        let shard = self.cells[at].decoded(&shard);
        if reads_standby(host, &volume, &shard) {
            self.cells[at].waiting = Some((member, Target::of(&shard), shard.active));
        } else {
            self.end_wait(at, member);
        }
    }
}
