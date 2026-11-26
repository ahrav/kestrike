//! The planned handoff and the parked owner process.
//!
//! A handoff episode withdraws the serving owner of one shard for `Cause::Planned`, closes its admission, records
//! the transfer and commits it to the record's named standby through `Client::transfer`, conditioned on the shard
//! record the owner's client read. The outgoing tenure settles on the acknowledged transfer, ends `Exit::Stopped` and
//! is torn down with no rerun. The target's standby wait then reads the restart role, and its next incarnation
//! restarts through the lineage arm.
//!
//! In the ended-target form the target's attach entry turns `Ended` between the transfer's reads and its write. The
//! target's restart then refuses at its record reads and parks: the process keeps the tenure slot its incarnation
//! took and runs one `host::serve::wait` period per view period until that wait reads another role or its host
//! crashes. A parked process issues no reservation command and publishes no status; the host rules
//! `PARKED_DEVICE` and `PARKED_STATUS` judge both on every run.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::failover::records::{EventKind, Host, ShardRecord, VolumeRecord};
use crate::failover::takeover::tests::holder_on;
use crate::host::{Exit, HostGate, Role};
use crate::storage::store::{Key, Outgoing};

use super::{Fleet, Live, Slots, Stopped};

/// One handoff episode as the host log lists it: the transfer the outgoing owner issued, or why it issued none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Handed {
    /// The round since the hosts started.
    pub(crate) round: u64,
    pub(crate) shard: u32,
    /// The outgoing owner's host.
    pub(crate) from: u64,
    /// The standby the shard record named.
    pub(crate) to: u64,
    /// The outgoing owner's tenure.
    pub(crate) tenure: crate::oracle::Tenure,
    /// The attempt counter of the record the transfer committed.
    pub(crate) attempts: Option<u32>,
    /// Whether the target's attach ended inside the transfer.
    pub(crate) ended: bool,
    /// Whether the store acknowledged the transfer and the outgoing owner settled on it.
    pub(crate) committed: bool,
    /// The exit `serve::ended` named for the outgoing tenure after the transfer.
    pub(crate) exit: Option<Exit>,
    /// Why no transfer was issued or the issued one failed.
    pub(crate) refused: Option<String>,
}

/// One park as the host log lists it, from the restart that ended with a parking exit to the park's end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Park {
    /// The round since the hosts started at which the park began.
    pub(crate) round: u64,
    pub(crate) shard: u32,
    pub(crate) host: u64,
    /// The restart's parking exit.
    pub(crate) exit: Exit,
    /// The view periods of `host::serve::wait` the park ran.
    pub(crate) periods: u32,
    /// The reservation commands the cell's table logged during the restart that parked and during each view period
    /// of the park. Commands other hosts issue on the volume between two periods are theirs and are not listed.
    pub(crate) commands: Vec<&'static str>,
    /// The round since the hosts started at which the park ended, and the exit of its last view period, or `None`
    /// for a crash of its host.
    pub(crate) left: Option<(u64, Option<Exit>)>,
}

/// A parked process the fleet still runs: the member's process for cell `at`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Parked {
    pub(crate) at: usize,
    pub(crate) member: usize,
    /// The tenure slot the parked process holds.
    pub(crate) slot: usize,
    /// Its entry in [`super::hosts::HostLog::parks`].
    pub(crate) entry: usize,
}

impl<'c> Fleet<'c> {
    /// The planned handoff of cell `at`'s serving tenure to the standby its shard record names. Once the GETs in
    /// flight settled, the owner's host client reads the shard record and the volume record; a record that names no
    /// standby, or a standby with no live enrolled pair, ends the episode with no transfer. The owner then withdraws
    /// for `Cause::Planned`, closes its admission and records the transfer, and the client commits it on the shard
    /// record it read. With `ended`, the target's attach entry turns `Ended` and every running agent takes the scaled
    /// restart grace after those reads and before that write. A committed transfer settles the owner, every host
    /// rereads the record, and a tenure that `serve::ended` names `Stopped` is torn down as `serve` ends it. An
    /// uncommitted transfer settles the withdrawn owner for its one same-host restart. The episode joins
    /// `HostLog::handoffs` either way.
    pub(super) fn hand_off(
        &mut self,
        live: &mut Live<'_>,
        at: usize,
        ended: bool,
    ) -> Result<(), Stopped> {
        self.drain(live)?;
        let shard = self.cells[at].placement.shard;
        let member = self.cells[at].holder;
        let from = self.topology.members[member].host;
        let mut handed = Handed {
            round: self.round - self.host_start,
            shard: shard.get(),
            from: from.get(),
            to: 0,
            tenure: crate::oracle::Tenure { g: 0, a: 0 },
            attempts: None,
            ended,
            committed: false,
            exit: None,
            refused: None,
        };
        let refused = |fleet: &mut Self, mut handed: Handed, why: String| {
            handed.refused = Some(why);
            fleet.log.handoffs.push(handed);
            Ok(())
        };
        if live[at].is_none() {
            return refused(self, handed, "no serving tenure".to_owned());
        }
        let mut client = self.client(member);
        let read = match client.read::<ShardRecord>(Key::Shard(shard)) {
            Ok(read) => read,
            Err(error) => return refused(self, handed, format!("{error:?}")),
        };
        let record = *read.value();
        let Some(target) = record.standby.filter(|_| record.owner == from) else {
            return refused(self, handed, format!("record {record:?}"));
        };
        handed.to = target.get();
        let enrolled = match client.read::<VolumeRecord>(Key::Volume(record.active)) {
            Ok(volume) => {
                let volume = volume.value();
                volume.live(target).is_some() && volume.enrolled(target).is_some()
            }
            Err(error) => return refused(self, handed, format!("{error:?}")),
        };
        if !enrolled {
            return refused(self, handed, "the target holds no enrolled pair".to_owned());
        }
        let serving = live[at].as_mut().expect("the serving tenure");
        handed.tenure = serving.tenure;
        let now = serving.turn * super::ROUND_US;
        use crate::failover::serving::{Cause, Event};
        serving
            .owner
            .authority_event(Event::Withdraw(Cause::Planned), now);
        serving.owner.close(now);
        if !serving.owner.transfer_submitted(target) {
            handed.exit = crate::host::serve::ended(&serving.owner);
            return refused(self, handed, "the owner recorded no transfer".to_owned());
        }
        let outgoing = Outgoing::of(serving.owner.tenure());
        if ended {
            self.end_attach_of(at, target);
            let unscaled = self.config.planted_at(super::Plant::UnscaledGrace, at);
            self.planted |= unscaled;
            let grace = super::hosts::HANDOFF_GRACE_ROUNDS * super::ROUND_US;
            if !unscaled {
                self.grace_us = Some(grace);
                for host in &mut self.hosts {
                    if let Some(agent) = host.agent.as_mut() {
                        agent.set_restart_grace(grace);
                    }
                }
            }
        }
        let gate = crate::failover::reconcile::StandbyGate::qualified();
        let transferred = client.transfer(&gate, &read, &outgoing, target);
        drop(client);
        let serving = live[at].as_mut().expect("the serving tenure");
        match transferred {
            Ok(transferred) => {
                handed.attempts = Some(transferred.committed().value().attempts);
                handed.committed =
                    (serving.owner).transfer_committed(&transferred, record.active, now);
            }
            Err(error) => handed.refused = Some(format!("{error:?}")),
        }
        // An uncommitted or unsettled transfer leaves the withdrawn tenure to its one same-host restart.
        if !handed.committed {
            serving.owner.transfer_settled();
        }
        let exit = crate::host::serve::ended(&serving.owner);
        handed.exit = exit.clone();
        let committed = handed.committed;
        self.log.handoffs.push(handed);
        if committed {
            self.reread_hosts(at);
        }
        if exit == Some(Exit::Stopped) {
            live[at].as_mut().expect("the serving tenure").duty_exit = Some(Exit::Stopped);
            let serving = live[at].take().expect("the serving tenure");
            let _ = self.tear_down(at, serving);
            self.release_watches(at);
        }
        Ok(())
    }

    /// Writes the `Ended` kind into `target`'s live attach entry of cell `at`'s volume record, the entry change
    /// `Reconciler::end_attach` writes.
    fn end_attach_of(&mut self, at: usize, target: Host) {
        let volume = self.cells[at].placement.volume;
        let mut client = crate::storage::store_tests::client(&self.store);
        let read = (client.read::<VolumeRecord>(Key::Volume(volume)))
            .expect("the fleet's store answers the volume read");
        let seq = read.value().live(target).expect("the target's live attach");
        let mut next = read.value().clone();
        let entry = (next.events.iter_mut())
            .find(|entry| entry.seq == seq)
            .expect("the live attach's entry");
        entry.kind = EventKind::Ended;
        (client.replace(&read, next)).expect("the attach end commits");
    }

    /// Parks `member`'s process for cell `at` after a restart on `grounds` that ended with the parking exit `exit`.
    /// The process keeps that ground's tenure slot, and the park's log entry lists the reservation commands the
    /// cell's table logged from index `from`, the log's length when the restart began; each view period of the park
    /// adds the commands logged inside it ([`Fleet::park_periods`]).
    pub(super) fn park<'w>(
        &mut self,
        slots: &Slots<'w>,
        (at, member, from): (usize, usize, usize),
        grounds: &'w super::super::Grounds,
        exit: &Exit,
    ) {
        let slot = slots.index_of(grounds);
        let entry = self.log.parks.len();
        let table = &self.cells[at].world.reservation;
        let commands = super::owners::commands_since(table, from);
        self.log.parks.push(Park {
            round: self.round - self.host_start,
            shard: self.cells[at].placement.shard.get(),
            host: self.topology.members[member].host.get(),
            exit: exit.clone(),
            periods: 0,
            commands,
            left: None,
        });
        self.parks.push(Parked {
            at,
            member,
            slot,
            entry,
        });
    }

    /// One view period of every park: `host::serve::wait` in the restart role over the host's standby-wait client,
    /// whose requests on the parked shard's records the cell excuses as it does a standby wait's. The reservation
    /// commands the cell's table logs inside the period join the park's list. A period that ends other than
    /// `Exit::Stopped` ends the park, and so does a crash of the host. A paused host runs no period.
    pub(super) fn park_periods(&mut self) {
        let mut index = 0;
        while index < self.parks.len() {
            let parked = self.parks[index];
            let up = self.hosts[parked.member].up;
            if up == super::hosts::Up::Down {
                self.leave_park(index, None);
                continue;
            }
            if up != super::hosts::Up::Running {
                index += 1;
                continue;
            }
            let cell = &self.cells[parked.at];
            let of = self.topology.members[parked.member];
            let holder = holder_on(cell.placement.volume, of.host, of.instance);
            let shard = cell.placement.shard;
            // No other actor runs inside this period, so the commands the table logs from here to the period's end
            // are the parked process's.
            let from = cell.world.reservation.borrow().log.len();
            let counts = super::owners::WaitCounts::default();
            let mut client = self.standby_client(parked.member, &counts);
            let stop = AtomicBool::new(false);
            let periods = std::cell::Cell::new(0_u32);
            let period = || {
                periods.set(periods.get() + 1);
                if periods.get() > 1 {
                    stop.store(true, Ordering::Release);
                }
            };
            let gate = HostGate::qualified();
            let exit = crate::host::wait(
                &gate,
                Role::Restart,
                (shard, &holder),
                &mut client,
                &stop,
                period,
            );
            drop(client);
            // The park's requests on its shard's records are the process's own, as a standby wait's are.
            self.cells[parked.at].excuse(&counts);
            let first = self.log.parks[parked.entry].periods == 0;
            if first
                && self
                    .config
                    .planted_at(super::Plant::ParkedCommand, parked.at)
            {
                let cell = &self.cells[parked.at];
                let (pair, _) = cell
                    .local_of(parked.member)
                    .expect("the parked process's local record");
                super::owners::report_in_wait(cell, pair);
            }
            self.log.parks[parked.entry].periods += 1;
            let table = &self.cells[parked.at].world.reservation;
            let issued = super::owners::commands_since(table, from);
            self.log.parks[parked.entry].commands.extend(issued);
            if exit == Exit::Stopped {
                index += 1;
                continue;
            }
            self.leave_park(index, Some(exit));
        }
    }

    /// Ends the park at `index` with its last period's `exit`, or with `None` at a crash of its host. The park's
    /// tenure slot is freed before the host loop's next step, and a park that ended with an exit queues the
    /// process's next incarnation from the round before this one, so the host loop runs it in this round.
    pub(super) fn leave_park(&mut self, index: usize, exit: Option<Exit>) {
        let parked = self.parks.remove(index);
        let rerun = exit.is_some();
        self.log.parks[parked.entry].left = Some((self.round - self.host_start, exit));
        self.unparked.push(parked.slot);
        if rerun {
            let (key, ended) = ((parked.at, parked.member), self.round.saturating_sub(1));
            self.refused.insert(key, (ended, false));
            self.rerun_starts.insert(key, ended);
        }
    }

    /// Frees the tenure slots of the parks that ended since the host loop last ran.
    pub(super) fn free_unparked(&mut self, slots: &mut Slots<'_>) {
        for slot in std::mem::take(&mut self.unparked) {
            slots.release_at(slot);
        }
    }
}
