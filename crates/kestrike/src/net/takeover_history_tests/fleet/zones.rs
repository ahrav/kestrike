//! A zone episode stops every host of one zone while the store and the reconcilers stay up. When the last host of
//! the zone is down the fleet opens an [`Outage`]. `Outage` records the down zone's commit count for shard records,
//! volume records and receipts, and the provider's call count. For each other zone, it records census and
//! shard-record commit counts, record tenures and routes, and serving tenures. When the hosts return the fleet
//! compares them, and [`ZoneLog`] holds the commits the outage made for the down zone and the shards and censuses
//! of another zone that changed. The outage closes in the round every host of its zone runs again, and the
//! comparison covers the rounds until then.
//!
//! The fleet queues each shard a returning host held when it stopped, and the run's decisions select the order of
//! the restart attempts. A host whose shard record names another owner refuses and serves nothing. A restart that
//! returns bumps the attempt, loads warm and sweeps its retained set, and the tenure then acknowledges one FILL and
//! one INVALIDATE.
//!
//! The fleet stamps each tenure's first admitted operation with the commit count of every coverage page of its
//! shard. It reads the counts when it submits the operation to the tenure: a GET's when the client accepts the send,
//! a FILL's before the publication starts, an INVALIDATE's before the owner takes its hold. It keeps the stamp once
//! the result shows the tenure admitted the operation: the GET settles with the object's exact bytes, the
//! publication returns, the owner acknowledges the INVALIDATE. The tenure admits an operation at or after its
//! submission, so the stamp bounds the admission from below. A tenure's fence commit on a page is the first version
//! of the page that carries the tenure's session, so a fence commit within the stamp precedes the admission. Of a
//! tenure's admitted operations the stamp is of the one submitted first.
//! Invariant: acknowledged coverage precedes a successor tenure's admission.

use crate::failover::records::{CoveragePage, Record};
use crate::failover::standbys::Zone;
use crate::failover::zone_loop::status::Blocker;
use crate::oracle::Tenure;
use crate::storage::store::Key;

use super::draws::{self, Tag};
use super::hosts::Up;
use super::oracles::{Admission, Admitted, PageFences};
use super::volumes::Restarted;
use super::{Fleet, Live, Plant, Seen, Slots, Stopped};

/// Whether a returning host whose record names another owner ended as a deposed host does: its role read named it
/// unnamed or standby, so its incarnation waited and ran no restart, or a restart its role read started refused
/// `Deposed` on a record that changed after that read.
pub(crate) fn deposed(check: &str) -> bool {
    check == "Deposed" || check == "Unnamed" || check.starts_with("Standby")
}

/// The entry a deposed host's incarnation leaves in [`ZoneLog::deposed`] when it acquired a tenure.
pub(crate) const RESTARTED: &str = "Restarted";

/// The rounds a lost zone stays down.
pub(crate) const ZONE_DOWN_ROUNDS: u64 = 60;

/// The rounds H3 stays down in [`Scenario::ZoneDeposed`](super::hosts::Scenario::ZoneDeposed) before its own crash
/// heals. H3 crashes at round 19 and its zone stops at round 72 and returns at round 132, so the crash heals at
/// round 109, inside the outage, and H3 returns with its zone, when the last crash holding it heals.
pub(crate) const DEPOSED_DOWN_ROUNDS: u64 = 90;

/// The counts the fleet holds from the round a zone's last host stopped until its hosts return.
pub(super) struct Outage {
    zone: Zone,
    /// The commits of the down zone's shard records, volume records and replacement receipts, and the provider's
    /// calls.
    commits: usize,
    calls: usize,
    /// Each other zone's census commit count, and each of its cells with the commit count of its shard record,
    /// volume record and receipt, its record's tenure and route, and its serving tenure.
    censuses: Vec<(Zone, usize)>,
    others: Vec<(usize, usize, Seen, Option<Tenure>)>,
    /// The length of the reconcilers' blocker log.
    blockers: usize,
}

/// One zone episode's log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ZoneLog {
    /// The shards of the zone whose every host stopped.
    pub(crate) down: Vec<u32>,
    pub(crate) returned: bool,
    /// The down zone's shards that took `NoEligibleHost` during the outage and carried it when the outage closed,
    /// and those that took and carried `VolumeImpaired`.
    pub(crate) unplaced: Vec<u32>,
    pub(crate) impaired: Vec<u32>,
    /// The commits of the down zone's shard records, volume records and receipts, and the provider calls, between
    /// the last host's stop and the return.
    pub(crate) down_writes: usize,
    pub(crate) down_calls: usize,
    /// The shards of another zone whose shard record, volume record or receipt took a commit, or whose route or
    /// serving tenure changed, during the outage, and the zones whose census took a commit.
    pub(crate) other_moved: Vec<u32>,
    pub(crate) other_censuses: Vec<u16>,
    /// Each restart of a returning owner that served: its shard, its host, its tenure, and the shard record's
    /// attempt count read just before the restart.
    pub(crate) restarts: Vec<(u32, u64, Tenure, u32)>,
    /// Each returning host whose shard record named another owner just before its incarnation: the shard, the host,
    /// the check, and that record's attempt count. The check is the waiting role from the role read, the refusal's
    /// blocker, the role read's error, or [`RESTARTED`] for an incarnation that acquired a tenure.
    pub(crate) deposed: Vec<(u32, u64, String, u32)>,
    /// The returning tenures that acknowledged a FILL and an INVALIDATE after their sweep.
    pub(crate) acknowledged: u32,
    /// The fence commits of the returning tenures.
    pub(crate) fence_writes: usize,
    /// The rounds from the return until no restart was queued and every shard of the returned zone served with a
    /// standby.
    pub(crate) settled_in: Option<u64>,
}

impl Fleet<'_> {
    /// The commits of cell `at`'s shard record, volume record and replacement receipt.
    fn cell_commits(&self, at: usize) -> usize {
        let store = self.store.0.borrow();
        let cell = &self.cells[at];
        let shard = cell.placement.shard;
        let keys = [
            Key::Shard(shard),
            Key::Volume(cell.placement.volume),
            Key::Replacement(shard),
        ];
        keys.iter().map(|key| store.commit_count(key)).sum()
    }

    fn zone_commits(&self, zone: Zone) -> usize {
        let cells = self.zone_cells(zone).into_iter();
        cells.map(|at| self.cell_commits(at)).sum()
    }

    fn census_commits(&self, zone: Zone) -> usize {
        self.store.0.borrow().commit_count(&Key::Standbys(zone))
    }

    /// Opens the outage of the first zone whose every host is down, once per run.
    pub(super) fn zone_down(&mut self, live: &Live<'_>) {
        if self.outage.is_some() || !self.zone_log.down.is_empty() {
            return;
        }
        let stopped = |zone: Zone| {
            let members = self.topology.members.iter().enumerate();
            let mut of_zone = members.filter(|(_, of)| of.zone == zone).peekable();
            of_zone.peek().is_some() && of_zone.all(|(member, _)| self.hosts[member].up == Up::Down)
        };
        let zones = (1..=self.config.shape.zones).map(Zone);
        let Some(zone) = zones.clone().find(|&zone| stopped(zone)) else {
            return;
        };
        let others: Vec<usize> = (0..self.cells.len())
            .filter(|&at| self.zone_of(at) != zone)
            .collect();
        self.outage = Some(Outage {
            zone,
            commits: self.zone_commits(zone),
            calls: self.zone_provider_calls(zone),
            censuses: (zones.filter(|&other| other != zone))
                .map(|other| (other, self.census_commits(other)))
                .collect(),
            others: (others.into_iter())
                .map(|at| {
                    let seen = self.cells[at].seen(&self.store);
                    let tenure = live[at].as_ref().map(|serving| serving.tenure);
                    (at, self.cell_commits(at), seen, tenure)
                })
                .collect(),
            blockers: self.recon.blockers.len(),
        });
        self.zone_log.down = (self.zone_cells(zone).into_iter())
            .map(|at| self.cells[at].placement.shard.get())
            .collect();
    }

    /// Closes the outage once every host of its zone runs again, and returns whether it closed: logs the commits the
    /// outage made for the down zone, the shards and censuses of every other zone it changed, and the blockers the
    /// down zone's shards took and still carry. A return of another zone's host, or of some of the zone's hosts,
    /// leaves the outage open.
    pub(super) fn zone_returned(&mut self, live: &Live<'_>) -> bool {
        let zone = self.outage.as_ref().map(|outage| outage.zone);
        let members = self.topology.members.iter().enumerate();
        let mut of_zone = members.filter(|(_, of)| Some(of.zone) == zone);
        if !of_zone.all(|(member, _)| self.hosts[member].up == Up::Running) {
            return false;
        }
        let Some(outage) = self.outage.take() else {
            return false;
        };
        self.zone_log.returned = true;
        self.returned_at = Some(self.round);
        self.zone_log.down_writes = self.zone_commits(outage.zone) - outage.commits;
        self.zone_log.down_calls = self.zone_provider_calls(outage.zone) - outage.calls;
        for (zone, commits) in outage.censuses {
            if self.census_commits(zone) != commits {
                self.zone_log.other_censuses.push(zone.0);
            }
        }
        for (at, commits, seen, tenure) in outage.others {
            let serving = live[at].as_ref().map(|serving| serving.tenure);
            let cell = &self.cells[at];
            let moved = self.cell_commits(at) != commits
                || cell.seen(&self.store) != seen
                || serving != tenure;
            if moved {
                self.zone_log.other_moved.push(cell.placement.shard.get());
            }
        }
        // A shard counts when the log entered the blocker during the outage and the cell carries it now, before any
        // returning restart or reconciler turn.
        let carried = |blocker: Blocker| {
            let taken = &self.recon.blockers[outage.blockers..];
            let entered = |shard: u32| {
                taken
                    .iter()
                    .any(|(_, of, b, _)| *of == shard && *b == blocker)
            };
            let cells = self.zone_cells(outage.zone).into_iter();
            cells
                .filter(|&at| self.cells[at].blocker == Some(blocker))
                .map(|at| self.cells[at].placement.shard.get())
                .filter(|&shard| entered(shard))
                .collect()
        };
        (self.zone_log.unplaced, self.zone_log.impaired) = (
            carried(Blocker::NoEligibleHost),
            carried(Blocker::VolumeImpaired),
        );
        true
    }

    /// Queues, for a host that returned, the restart of each shard it held when it stopped.
    pub(super) fn queue_returns(&mut self, member: usize) {
        let (due, held): (Vec<_>, Vec<_>) =
            (self.held_at_stop.drain(..)).partition(|(_, of)| *of == member);
        self.held_at_stop = held;
        self.returns.extend(due);
        self.returns.sort_unstable();
    }

    /// The next restart of a returning host, a decision among the queued ones.
    pub(super) fn next_return(&mut self) -> Result<Option<(usize, usize)>, Stopped> {
        if self.returns.is_empty() {
            return Ok(None);
        }
        let values: Vec<u64> = (self.returns.iter())
            .map(|&(at, member)| self.shard_of(at) * 1_000 + member as u64)
            .collect();
        let mut draws = self.draws.take().expect("the run's decisions");
        let picked = draws.pick(draws::NEXT, Tag::Shard, &values);
        self.draws = Some(draws);
        Ok(Some(self.returns.remove(picked?)))
    }

    /// `member`'s restart of cell `at` after its return. A tenure that served then acknowledges one FILL of a new
    /// object and one INVALIDATE of its second checkpoint object.
    pub(super) fn restart_returned<'w>(
        &mut self,
        live: &mut Live<'w>,
        slots: &mut Slots<'w>,
        (at, member): (usize, usize),
    ) -> Result<(), Stopped> {
        let shard = self.cells[at].placement.shard.get();
        let host = self.topology.members[member].host.get();
        let (tenure, from) = match self.restart_by(live, slots, at, member)? {
            Restarted::Served { tenure, from } => (tenure, from),
            Restarted::Deposed { check, attempts } => {
                let check = check.unwrap_or_else(|| RESTARTED.to_owned());
                (self.zone_log.deposed).push((shard, host, check, attempts));
                return Ok(());
            }
            Restarted::Held => return Ok(()),
        };
        self.zone_log.restarts.push((shard, host, tenure, from));
        let fill = self.config.shape.objects + 2;
        self.zone_log.acknowledged += u32::from(self.acknowledge(live, at, (fill, 2)));
        Ok(())
    }

    /// Logs the rounds since the return once no restart is queued and every shard of the returned zone serves with a
    /// standby.
    pub(super) fn zone_settled(&mut self, live: &Live<'_>) {
        let Some(returned) = self.returned_at else {
            return;
        };
        if self.zone_log.settled_in.is_some() || !self.returns.is_empty() {
            return;
        }
        let down = &self.zone_log.down;
        let mut cells = (0..self.cells.len())
            .filter(|&at| down.contains(&self.cells[at].placement.shard.get()));
        if cells.all(|at| self.served_with_standby(live, at)) {
            self.zone_log.settled_in = Some(self.round - returned);
        }
    }

    /// The commit count of each coverage page of cell `at`'s shard, which the fleet reads when it submits an
    /// operation to the shard's tenure. A run with one zone stamps no admission and reads no count.
    pub(super) fn page_counts(&self, at: usize) -> Vec<usize> {
        if !self.config.zoned() {
            return Vec::new();
        }
        let shard = self.cells[at].placement.shard;
        let store = self.store.0.borrow();
        let pages = 0..self.cells[at].pages;
        pages
            .map(|page| store.commit_count(&Key::Page(shard, page)))
            .collect()
    }

    /// Stamps `tenure`'s first admitted operation on cell `at` with `pages`, the [`Fleet::page_counts`] read when the
    /// operation was submitted. Of two admitted operations of one tenure the stamp keeps the one submitted first,
    /// whose counts are the lower ones, whichever result the fleet observes first.
    pub(super) fn admit(
        &mut self,
        at: usize,
        tenure: Tenure,
        admitted: Admitted,
        pages: Vec<usize>,
    ) {
        if !self.config.zoned() {
            return;
        }
        let shard = self.cells[at].placement.shard;
        let first = Admission {
            shard,
            tenure,
            admitted,
            pages,
        };
        let mut stamped = self.admissions.iter_mut();
        match stamped.find(|of| of.shard == shard && of.tenure == tenure) {
            Some(known) if first.pages.iter().sum::<usize>() < known.pages.iter().sum() => {
                *known = first;
            }
            Some(_) => {}
            None => self.admissions.push(first),
        }
    }

    /// The fence of every committed version of each coverage page of each shard, read without a store request.
    pub(super) fn page_fences(&self) -> Vec<PageFences> {
        let store = self.store.0.borrow();
        let fences = |key: Key| {
            let versions = store.versions(&key).iter();
            versions
                .map(|item| {
                    CoveragePage::decode(&item.value)
                        .expect("a stored page")
                        .fence
                })
                .collect()
        };
        (self.cells.iter())
            .map(|cell| {
                let shard = cell.placement.shard;
                let pages = (0..cell.pages).map(|page| fences(Key::Page(shard, page)));
                (shard, pages.collect())
            })
            .collect()
    }

    /// The early-admission plant: the planted shard's first returning tenure's stamp reads zero commits on every
    /// page, so its first admitted operation precedes each of its fence commits.
    pub(super) fn plant_admission(&mut self) {
        let super::Profile::Hostile(Plant::EarlyAdmission, at) = self.config.profile else {
            return;
        };
        let Some(cell) = self.cells.get(at as usize) else {
            return;
        };
        let shard = cell.placement.shard;
        let mut returned = self.zone_log.restarts.iter();
        let Some(&(_, _, tenure, _)) = returned.find(|(of, ..)| *of == shard.get()) else {
            return;
        };
        let mut stamped = self.admissions.iter_mut();
        if let Some(admission) = stamped.find(|of| of.shard == shard && of.tenure == tenure) {
            admission.pages.iter_mut().for_each(|count| *count = 0);
            self.planted = true;
        }
    }
}
