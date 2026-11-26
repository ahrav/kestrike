//! The second owner of a two-owner mixed scene: an owner of the scripted
//! owner's configuration over its own storage, device, media and two
//! links, with its own two clients, driven by the same turn controller
//! from the same chooser and judged against the same content registry.
//!
//! Every peer poll, client poll, disk service call, disk execute, post and
//! admission and NIC return is one selected event, proposed under the same
//! preconditions the scripted owner's are. A peer event names the peer in
//! its candidate: its own workload codes, a disk ordinal whose top byte is
//! one, or a link index past the scripted owner's two. The peer publishes
//! the resident object before the run and opens its clients' sessions
//! through the controller. Its stopped boundaries run the registry and
//! media check every mixed run uses, and its link and device audits join
//! the run's audit; scripted holds, closes and stops act on the scripted
//! owner only, so the peer's custody stays its own.

use std::cell::RefCell;
use std::rc::Rc;

use crate::sim::choice::{Candidate, Domain};
use crate::storage::owner_fixture::{Device, publish, set_clock};

use super::super::audit::{Reason, Verdict};
use super::super::link::Net;
use super::super::observe::{Failure, Lenses, Registry, boundary};
use super::super::owner::{MAINTAIN_REST_US, OwnerConfig};
use super::super::owner_tests::{key, payload};
use super::super::put_tests::Scene;
use super::super::restart::Fresh;
use super::{
    LINK_TURN_US, PEER_CLIENT_POLL, PEER_OWNER_POLL, PEER_SERVICE, Plan, STAGES, candidate,
    check_turn_limits, client_due, nic_return, owner_ready, poll_owner, select_disk,
};

/// The top byte of a disk ordinal, which every ordinal below 2^56 leaves
/// zero, holds one in each of the peer device's candidates.
const DEVICE: usize = 2;

/// The peer's links follow the scripted owner's two in link indices.
pub(super) const NETS: u8 = 2;

/// The second owner, its due times and its boundary lenses.
pub(super) struct Peer<'s, 'm> {
    pub(super) scene: Scene<'s, 'm>,
    owner_due: u64,
    service_due: u64,
    lenses: Lenses,
}

impl<'s, 'm> Peer<'s, 'm> {
    /// The peer over `fresh` at `start`: its device over fresh media holds
    /// the resident object under key 1, its owner starts under `config`,
    /// and its links take `plan`'s link settings.
    pub(super) fn started(
        fresh: Fresh<'s, 'm>,
        config: OwnerConfig,
        plan: &Plan,
        start: u64,
    ) -> Self {
        let mut device = Device::new(fresh.storage, fresh.buffers);
        publish(fresh.storage, &mut device, &key(1), 0, &payload(1000, 1));
        let scene = super::relaunch::started(device, fresh, config, start, super::ticks(start));
        super::wire(plan, &scene.nets);
        Self {
            scene,
            owner_due: start,
            service_due: start,
            lenses: Lenses::default(),
        }
    }

    /// Adds every peer event runnable at `now` to `out`.
    pub(super) fn runnable(&self, now: u64, out: &mut Vec<Candidate>) {
        let open = self.scene.owner.quiesce().is_none();
        if owner_ready(&self.scene, open, self.owner_due, now) {
            out.push(candidate(PEER_OWNER_POLL, 0, 0));
        }
        for client in 0..2 {
            if client_due(&self.scene, client, now) {
                out.push(candidate(PEER_CLIENT_POLL, client, 0));
            }
        }
        if self.service_due <= now {
            out.push(candidate(PEER_SERVICE, 0, 0));
        }
        for (at, net) in self.scene.nets.iter().enumerate() {
            for nth in 0..net.borrow().withheld() {
                out.push(nic_return(at + usize::from(NETS), nth));
            }
        }
        for stage in STAGES {
            for mut disk in self.scene.control.candidates(stage) {
                assert_eq!(disk.0[DEVICE], 0, "a disk ordinal below 2^56");
                disk.0[DEVICE] = 1;
                out.push(disk);
            }
        }
    }

    /// The peer's earliest due time after `now`.
    pub(super) fn next_due(&self, now: u64) -> Option<u64> {
        let clients = self
            .scene
            .clients
            .iter()
            .filter_map(|client| client.next_deadline_us());
        let arrivals = self
            .scene
            .nets
            .iter()
            .flat_map(|net| {
                let net = net.borrow();
                [net.next_arrival(), net.next_return()]
            })
            .flatten()
            .map(|turn| turn * LINK_TURN_US);
        [self.owner_due, self.service_due]
            .into_iter()
            .chain(clients)
            .chain(arrivals)
            .filter(|&due| due > now)
            .min()
    }

    /// Moves the peer's link clocks to `now` and checks its stopped
    /// boundary against `registry`.
    ///
    /// # Errors
    ///
    /// The boundary check's failure.
    pub(super) fn advance(&mut self, now: u64, registry: &Registry) -> Result<(), Failure> {
        for net in &self.scene.nets {
            net.borrow_mut().advance(now / LINK_TURN_US);
        }
        self.boundary(registry)
    }

    /// At the peer's stopped boundary, `boundary` checks the peer's media
    /// against `registry`.
    pub(super) fn boundary(&mut self, registry: &Registry) -> Result<(), Failure> {
        boundary(&self.scene.media(), registry, &mut self.lenses).map(drop)
    }

    pub(super) fn accounts(&self) -> Result<(), Failure> {
        self.scene.accounts()
    }

    /// `swallow_next` arms the peer owner's multiplexer to drop its next
    /// lease.
    pub(super) fn swallow_next(&mut self) {
        self.scene.owner.transport_mut().swallow_next();
    }

    pub(super) fn swallowed(&self) -> bool {
        self.scene.owner.transport().swallowed()
    }

    pub(super) fn swallow_unarmed(&self) -> bool {
        self.scene.owner.transport().swallow_unarmed()
    }

    pub(super) fn set_clock(&self, tick: u64) {
        set_clock(self.scene.storage, &[Some(tick)]);
    }

    /// Whether `event` is a peer event.
    pub(super) fn owns(event: &Candidate) -> bool {
        let [domain, code, actor, ..] = event.0;
        if domain == Domain::Disk as u8 {
            return event.0[DEVICE] == 1;
        }
        if domain == Domain::Link as u8 {
            return actor >= NETS;
        }
        domain == Domain::Workload as u8
            && matches!(code, PEER_OWNER_POLL | PEER_CLIENT_POLL | PEER_SERVICE)
    }

    /// Applies peer event `event` at `now`, asserting each owner poll's
    /// turn limits under `batch` sends and `wake` wake visits. Returns the
    /// event's outcome code and whether it made progress.
    pub(super) fn apply(
        &mut self,
        event: Candidate,
        now: u64,
        (batch, wake): (u64, u32),
    ) -> (u64, bool) {
        let [domain, code, actor, ..] = event.0;
        if domain == Domain::Disk as u8 {
            let mut own = event;
            own.0[DEVICE] = 0;
            return (select_disk(&self.scene.control, &own), false);
        }
        if domain == Domain::Link as u8 {
            let nth = u32::from_be_bytes(event.0[3..7].try_into().expect("four bytes"));
            self.scene.nets[usize::from(actor - NETS)]
                .borrow_mut()
                .return_tx(nth as usize);
            return (u64::from(nth) + 1, true);
        }
        match code {
            PEER_OWNER_POLL => {
                let (before, report, due, outcome) = poll_owner(&mut self.scene, now);
                check_turn_limits(&self.scene.owner, (&before, &report), batch, wake);
                self.owner_due = due;
                (outcome, false)
            }
            PEER_CLIENT_POLL => {
                let report = self.scene.clients[usize::from(actor)].poll(now);
                (
                    u64::from(report.received) | u64::from(report.sent) << 32,
                    false,
                )
            }
            PEER_SERVICE => {
                let calls = self.scene.control.driver_calls();
                self.scene.owner.service_disk();
                self.service_due = now + MAINTAIN_REST_US;
                ((self.scene.control.driver_calls() - calls) as u64, false)
            }
            code => unreachable!("peer event code {code}"),
        }
    }

    /// Both peer links' verdicts and the peer device's audit under the
    /// `declared` production outcomes.
    pub(super) fn judged(&self, declared: &[Reason]) -> Verdict {
        super::judged(
            &self.scene.nets,
            &self.scene.control,
            super::PEER_AUDIT_DEVICE,
            declared,
        )
    }

    /// The peer's links, for their draw errors.
    pub(super) fn nets(&self) -> &[Rc<RefCell<Net<'m>>>; 2] {
        &self.scene.nets
    }
}
