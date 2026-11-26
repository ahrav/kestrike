//! The serving tenure drains the inbox and publishes status during [`Duties::turn`]. The status's entry reads the
//! driver's part from [`Duties::observed`], and a part the duties do not hold yet reads unavailable.
//!
//! - GATE-BEFORE-STATUS: the publication tests the status period against the turn's time, the phase against the
//!   serving machine's state and the owner's state against the exits of [`serve::ended`](super::super::serve::ended)
//!   before it builds anything, so on a turn between statuses it reads no clock. On a turn that builds a status it
//!   takes one serving-clock reading, which dates the status's ages and its entry.
//! - FINAL-STATUS-KEPT: a turn that ends the tenure builds a status whatever the period, and a status the held cell
//!   refuses on that turn stays with the duties for [`Duties::take_unpublished`]. A turn ends the tenure when the
//!   duties return an exit, or when the owner's state at the publication names one through
//!   [`serve::ended`](super::super::serve::ended), the reading the serving loop takes after the duties: a lost
//!   device, a poisoned owner, or an authority that withdrew or closed with an exit.

use super::super::link::{Inbound, Link, Request, Status};
use super::Duties;
use crate::failover::report::{Observed, Phase, RecoveryStatus};
use crate::failover::serving::{Event, State};
use crate::net::{Datagrams, Owner};
use crate::storage::store::{Store, WatermarkLog};
use crate::storage::{Disk, Platform};

pub const STATUS_US: u64 = 1_000_000;

/// The link an owner process publishes its status to and drains its inbox from.
pub struct Linked<'l> {
    pub link: &'l Link,
    pub pid: u32,
    /// The status period on the serving clock, in microseconds. The publisher caps it at [`STATUS_US`], the period
    /// the agent's staleness bound counts in, so a live owner's status stays fresh between publications, and reads
    /// zero as [`STATUS_US`].
    pub status_us: u64,
    pub recovery: Option<RecoveryStatus>,
}

/// A part of [`Observed`] a planted control publishes as zero or clear while the duties hold none.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Zeroed {
    Store,
    Alarm,
    Enumeration,
}

#[cfg(test)]
thread_local! {
    pub(super) static ZEROED: std::cell::Cell<Option<Zeroed>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn zeroed(observed: Observed) -> Observed {
    use crate::failover::report::Enumeration;
    use crate::storage::store::{Alarm, Tally};
    match ZEROED.with(std::cell::Cell::get) {
        Some(Zeroed::Store) => Observed {
            store: observed.store.or(Some(Tally::default())),
            ..observed
        },
        Some(Zeroed::Alarm) => Observed {
            alarm: observed.alarm.or(Some(Alarm::Clear)),
            ..observed
        },
        Some(Zeroed::Enumeration) if observed.enumeration == Enumeration::Unavailable => Observed {
            enumeration: Enumeration::Matches,
            ..observed
        },
        Some(Zeroed::Enumeration) | None => observed,
    }
}

pub(super) struct Linking<'l> {
    linked: Linked<'l>,
    status_at: u64,
    phase: Option<Phase>,
    /// The status of the turn that ended the tenure with an exit of the duties or of the owner's state, which the
    /// held cell refused.
    unpublished: Option<Status>,
}

impl<'l, S: Store, L: WatermarkLog, P: Platform> Duties<'l, S, L, P> {
    pub fn linked(mut self, linked: Linked<'l>) -> Self {
        self.linking = Some(Linking {
            linked,
            status_at: 0,
            phase: None,
            unpublished: None,
        });
        self
    }

    /// The driver's part of the owner's entry. `enumeration` is the listing result of the last poll: the check of the
    /// listing it judged, `Unlisted` when it judged none after a listing call completed (a refused call, a reply past
    /// the listing deadline or a listing older than the listing period), and unavailable before. It is also
    /// unavailable when the view's volume read failed, the poll left a listed record unjudged, and the check found
    /// neither a foreign nor a duplicate record: a clean result would claim that no other record is listed. `alarm`
    /// is the client's alarm after the last adopted lane job, and `store` that copy's tally gain over the baseline
    /// taken when the tenure open started; each is unavailable before its sources exist. `roll_due` is unavailable
    /// until a suffix step sampled the signals, unless a capture refusal set it.
    pub fn observed(&self) -> Observed {
        let monitors = self.lane.monitors();
        let observed = Observed {
            enumeration: self.enumeration,
            alarm: monitors.map(|monitors| monitors.alarm),
            store: (self.baseline.zip(monitors))
                .map(|(baseline, monitors)| monitors.outcomes.since(&baseline)),
            recovery: (self.linking.as_ref()).and_then(|linking| linking.linked.recovery),
            captures: self.captures(),
            quarantine: self.quarantine(),
            suffix_due: self.due,
            roll_due: (self.sampled || self.roll_due).then_some(self.roll_due),
            roll_active: Some(self.restart_active()),
        };
        #[cfg(test)]
        let observed = zeroed(observed);
        observed
    }

    /// The latest `Request` the inbox delivered and no call took yet; a later delivery replaces an untaken one. Duties
    /// built through [`Duties::requesting`] take every delivered request themselves, in delivery order, at the start of
    /// each turn, so this returns `None` for them.
    pub fn take_request(&mut self) -> Option<Request> {
        self.request.take()
    }

    /// The status of the turn that ended the tenure, when the link side held the cell at that turn's publication:
    /// the turn on which the duties returned an exit, or on which the owner's state named one
    /// ([`serve::ended`](super::super::serve::ended)) when the duties published. That turn has no successor to
    /// publish it, so the caller takes it after the serving loop and publishes it there, where a retry delays no
    /// owner turn.
    pub fn take_unpublished(&mut self) -> Option<Status> {
        self.linking.as_mut()?.unpublished.take()
    }

    pub(super) fn inbound<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        owner: &mut Owner<'_, 'a, '_, P, D, T>,
        now: u64,
    ) {
        let Some(linking) = self.linking.as_ref() else {
            return;
        };
        let keyed = (self.rolling.as_deref()).is_some_and(super::roll::Roll::takes_requests);
        let (request, delivered) = (&mut self.request, &mut self.delivered);
        linking.linked.link.inbox.drain(|message| match message {
            Inbound::Peer { read_at } => {
                owner.authority_event(Event::Peer { read_at }, now);
            }
            Inbound::Request(bytes) if keyed => {
                if delivered.len() < delivered.capacity() {
                    delivered.push(bytes);
                }
            }
            Inbound::Request(bytes) => *request = Some(bytes),
            // The serving tenure retains its shard on nomination.
            Inbound::Nominate(_) => {}
        });
    }

    /// Publishes the owner's status when the status period passed or the phase changed, and on the turn that ends
    /// the tenure, whatever the period. `last` says the duties return an exit on this turn; the turn also ends the
    /// tenure when the owner's state names an exit ([`serve::ended`](super::super::serve::ended)), as the serving
    /// loop reads it after the duties. The period, phase and exit test reads the turn's time, the serving machine's
    /// state and the owner's loss and poison flags, so a turn between statuses returns from it. A turn that builds a
    /// status takes one serving-clock reading, which dates the status's ages and its entry. When the held cell
    /// refuses a status, a later turn builds the next one, and the status of the turn that ends the tenure waits for
    /// [`Duties::take_unpublished`].
    pub(super) fn publish<'a, D: Disk, T: Datagrams<'a>>(
        &mut self,
        owner: &Owner<'_, 'a, '_, P, D, T>,
        now: u64,
        last: bool,
    ) {
        let Some(linking) = self.linking.as_ref() else {
            return;
        };
        let phase = match owner.authority_state() {
            State::PreBoundary | State::Recovering => Phase::Recovering,
            State::Serving => Phase::Serving,
            State::Withdrawn => Phase::Withdrawn,
            State::Closed => Phase::Closing,
        };
        let last = last || super::super::serve::ended(owner).is_some();
        if !last && now < linking.status_at && linking.phase == Some(phase) {
            return;
        }
        let (link, pid) = (linking.linked.link, linking.linked.pid);
        let observed = self.observed();
        let authority = owner.authority_report();
        let reads = owner.volume_report();
        let commands = owner.report().retained.commands;
        let status = Status {
            tenure: Some(authority.tenure),
            target: self.target,
            report_age_us: authority.report_age_us,
            read_age_us: authority.freshness_age_us,
            io: reads.reads_done + reads.reads_failed + reads.writes_done + reads.writes_failed,
            completions: owner.answered(),
            pending: u64::from(commands) + u64::from(owner.census().live()),
            entry: owner.report_entry_at(authority, now, &observed),
            ..Status::idle(
                owner.tenure().shard(),
                self.records.holder.volume,
                pid,
                phase,
            )
        };
        let published = link.status.publish(status);
        let Some(linking) = self.linking.as_mut() else {
            return;
        };
        if published {
            linking.phase = Some(phase);
            let period = match linking.linked.status_us {
                0 => STATUS_US,
                period => period.min(STATUS_US),
            };
            linking.status_at = now.saturating_add(period);
        } else if last {
            linking.unpublished = Some(status);
        }
    }
}
