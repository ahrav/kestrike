//! An in-memory datagram network for endpoint tests: two ends, each naming the other as peer 0, joined by queues bounded by `capacity` datagrams per direction, with faults drawn as recorded choices.
//!
//! Each direction's [`Faults`] cover datagrams toward one end. Loss, a burst of losses after one, the loss of a resend, duplication, reordering, delay in turns, a stale replay of an earlier datagram and the truncation flag are drawn at send; truncation takes effect at delivery and keeps the data room's first bytes. A would-block or failing call is drawn on each send that reaches the direction and each receive with a slot to fill; an empty call returns zero and a refused leading datagram fails the call before any fault is drawn. A dead end's sends vanish and datagrams sent to it are dropped. Every draw is a [`Chooser`] decision at the link's registered sites ([`sites`]): a fault percentage of zero draws nothing, and the same root, or the same tape, replays the same schedule. The link keeps its own allocations out of the per-thread count, as a device would, so hot-path tests over it measure only the endpoints.
//!
//! The duplicate draw, then the loss draw or a burst's drop, then the resend draw, seed a base decision; an ordered rule [`Chain`] then decides each datagram once, its last rule committing the decision ([`super::rules`]), and the stale, delay, truncation and reorder draws follow for the fields the decision leaves unset. A datagram the decision keeps reserves every queue entry, copied byte and retained transmit slot its original, duplicate and stale copies need, together, before the link takes any device reference; a reservation that fails ends the accepted prefix with its bound as the reason. Every outcome other than a plain delivery bumps its report counter, if it has one, and lands in the link's [`Audit`] with its origin class and reason, in one step. A draw the chooser refuses latches as the link's [`draw_error`](Net::draw_error) and leaves its fault off. A network built with its own chooser ([`network`]) keeps that chooser's tape to itself; one built with a run's chooser ([`network_drawn`]) records every draw on the run's tape.
//!
//! A burst follows a loss. When a datagram's committed decision is the loss fault and the direction's `burst` is above zero, the link draws a run of 0 to `burst`, and each of that many later datagrams toward that end starts its decision dropped as a burst and makes no loss draw. Only a committed loss arms a run, so each [`Reason::LostBurst`] record follows a [`Reason::Lost`] in carried order. Every datagram that reaches the draws takes one of the run, one a rule delivers included; a dead-end datagram and an injected one take none, and a change of the direction's faults ends the run. Every datagram that reaches the draws, a dropped or unparsed one included, takes a slot of the direction's resend window at every setting, and while the direction's `resend_loss` is above zero a resend no earlier draw dropped draws its loss at its own site ([`ResendKey`]). The rules decide after both, so a rule that delivers clears either drop, and the report's `lost` counts both.
//!
//! The link stands in for a zero-copy device. A send copies the header and inline pieces, and takes a device reference to each retained piece's source before it queues the datagram; a datagram it refuses holds none. Delivery reads the retained bytes then, as a device reads them at transmit, applies any corruption to the delivered copy, and moves the references to the device's return queue; [`TxRelease`] returns them at delivery, makes each returnable after a drawn delay, or holds them until a selected [`Net::return_tx`] or [`Net::release_tx`]; a returnable reference returns on its sender's next `reclaim`. [`TxRelease::Premature`] is the negative control: it returns each reference at send and still reads the bytes at delivery. Each direction counts, and audits, the datagrams whose bytes the device read at delivery differ from their bytes at send.
//!
//! A receive writes each datagram into a buffer posted from the caller's pool, as the device would, and hands it back as a lease. An end with a receive ring of `n` posts up to `n` buffers from the caller's pool, refilling every free entry before and after each call that reaches delivery, and keeps them posted across calls; a datagram that arrives while its ring is empty is dropped and counted as missed.

use std::cell::RefCell;
use std::rc::Rc;

use crate::sim::choice::{ChoiceError, Chooser, Domain, Site};
use crate::storage::{NicHold, RxPosted};

use super::audit::{Audit, Class, Reason, Source, Verdict};
use super::datagram::{DatagramError, Datagrams, Outgoing, Payload, PeerId, Received};
use super::packet::{PacketLease, PacketPool};
use super::rules::{Bound, Chain, Corruption, Decision, Dropped, MANIFEST, Message};

/// A chooser the link shares with the run that drives it.
pub(crate) type Draws = Rc<RefCell<Chooser>>;

/// A fault the link draws, one site per fault and direction. A new draw goes last, so every recorded tape keeps
/// its sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub(super) enum Draw {
    Loss = 1,
    Duplicate,
    Reorder,
    ReorderAt,
    Delay,
    Stale,
    Truncate,
    WouldBlock,
    Error,
    Release,
    Burst,
    Resend,
}

const DRAWS: [Draw; 12] = [
    Draw::Loss,
    Draw::Duplicate,
    Draw::Reorder,
    Draw::ReorderAt,
    Draw::Delay,
    Draw::Stale,
    Draw::Truncate,
    Draw::WouldBlock,
    Draw::Error,
    Draw::Release,
    Draw::Burst,
    Draw::Resend,
];

/// The site of `draw` toward end `toward` on link `actor`.
pub(super) fn site(actor: u16, draw: Draw, toward: usize) -> Site {
    Site {
        domain: Domain::Link,
        actor,
        site: (draw as u16) << 1 | toward as u16,
    }
}

/// Every site link `actor` draws at.
pub(crate) fn sites(actor: u16) -> Vec<Site> {
    DRAWS
        .iter()
        .flat_map(|&draw| [0, 1].map(|toward| site(actor, draw, toward)))
        .collect()
}

/// A link's resource bounds beyond its queue capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LinkLimits {
    /// Copied header and inline bytes in flight per direction.
    pub(crate) copy_bytes: usize,
    /// Retained transmit references the link holds at once, queued or awaiting return.
    pub(crate) tx_slots: usize,
}

/// One delivered copy the link damaged: its corruption, its truncation flag, the end it reached and its bytes before the data room's zero fill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Damaged {
    pub(crate) corruption: Option<Corruption>,
    pub(crate) truncated: bool,
    pub(crate) toward: usize,
    pub(crate) bytes: Vec<u8>,
}

/// How one datagram left the network toward its receiving end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Landed {
    Delivered,
    /// Delivered with its tail cut at the receive buffer or by a fault.
    Truncated,
    /// Dropped because the receiving end's ring was empty.
    Missed,
}

/// One entry of the network's ordered delivery log: the direction, the
/// carried ordinal of the send the datagram rode, a digest of the bytes
/// the receive buffer holds, a grown tail's zero fill included (the
/// datagram's bytes for a miss), and how it left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Delivery {
    pub(crate) toward: usize,
    pub(crate) ordinal: u64,
    pub(crate) digest: [u8; 32],
    pub(crate) landed: Landed,
}

impl Delivery {
    /// The entry for `bytes` followed by `zeros` zero bytes.
    fn of(toward: usize, ordinal: u64, (bytes, zeros): (&[u8], usize), landed: Landed) -> Self {
        use sha2::{Digest, Sha256};
        const ZERO: [u8; 256] = [0; 256];
        let mut digest = Sha256::new();
        digest.update(bytes);
        let mut zeros = zeros;
        while zeros > 0 {
            let run = zeros.min(ZERO.len());
            digest.update(&ZERO[..run]);
            zeros -= run;
        }
        Self {
            toward,
            ordinal,
            digest: digest.finalize().into(),
            landed,
        }
    }
}

/// Bounds that never refuse a fixture's traffic.
pub(crate) const UNBOUNDED: LinkLimits = LinkLimits {
    copy_bytes: usize::MAX,
    tx_slots: usize::MAX,
};

/// When delivered datagrams' device references return.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum TxRelease {
    /// At delivery.
    #[default]
    AtDelivery,
    /// Each returnable after a drawn delay of at most this many turns, so references return late and out of order, on the sender's `reclaim`.
    Delayed(u64),
    /// Until a selected [`Net::return_tx`], [`Net::release_tx`] or the network's drop.
    Withheld,
    /// At send, before the device reads the bytes: the negative control for retention.
    Premature,
}

/// One direction's faults, each a percentage except `delay`, the most turns a datagram waits, and `burst`, the
/// most further datagrams one loss takes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Faults {
    pub(crate) loss: u64,
    pub(crate) duplicate: u64,
    pub(crate) reorder: u64,
    pub(crate) delay: u64,
    pub(crate) stale: u64,
    pub(crate) truncate: u64,
    pub(crate) would_block: u64,
    pub(crate) error: u64,
    /// When a datagram's committed decision is a loss, the link draws a run of 0 to `burst` later datagrams
    /// toward the same end, each of which starts its decision dropped as a burst in place of the loss draw.
    pub(crate) burst: u32,
    /// The chance a resend is lost, drawn only for a datagram whose resend key the link carried before toward the same end: see
    /// [`ResendKey`].
    pub(crate) resend_loss: u64,
}

/// A datagram's resend key: the kind, session epoch, request, allocation, fragment index and offset of the header
/// the rules decode from it, which for a packed datagram is its first GET frame's.
/// Each datagram that reaches the draws toward an end takes one of that direction's last [`MANIFEST`]`.captures`
/// window slots at every setting, a dropped one included, and a datagram that decodes to no header takes an empty
/// slot. A datagram is a resend when its key matches a key already in the window; a datagram with no decoded
/// header is a first send. A packed datagram whose first frame's key is in the window is a resend whichever frames
/// follow it, and a GET carried only behind another frame leaves no key in the window. While the direction's resend loss is above zero, a resend no earlier draw dropped makes the
/// resend draw. Distinct frames that share all six fields count as resends: a grant-only ACK, a PUT ACK or PUT
/// READY whose grant alone moved, a new session's HELLO, two ERROR frames of one request, ownership frames, and a
/// PUT DATA resend that differs only in body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResendKey {
    kind: super::frame::Kind,
    epoch: u64,
    request: u64,
    allocation: u64,
    index: u32,
    offset: u64,
}

impl ResendKey {
    pub(crate) fn of(header: &super::frame::Header) -> Self {
        Self {
            kind: header.kind,
            epoch: header.epoch,
            request: header.request,
            allocation: header.allocation,
            index: header.index,
            offset: header.offset,
        }
    }
}

/// What the network did, by direction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct NetReport {
    pub(crate) full: u64,
    pub(crate) lost: u64,
    pub(crate) duplicated: u64,
    pub(crate) stale: u64,
    pub(crate) reordered: u64,
    pub(crate) delayed: u64,
    pub(crate) truncated: u64,
    pub(crate) blocked: u64,
    pub(crate) errors: u64,
    /// Datagrams whose bytes the device read at delivery differ from their bytes at send; a link corruption of the delivered copy counts apart.
    pub(crate) altered: u64,
    /// Datagrams dropped because the receiving end's ring was empty.
    pub(crate) missed: u64,
    /// Leases a receive handed back toward this direction's end, truncated or whole: each delivery once, a
    /// duplicate, a stale copy and an injected datagram each as its own.
    pub(crate) delivered: u64,
}

/// When a delivered reference becomes returnable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Due {
    At(u64),
    /// At a selected [`Net::return_tx`].
    Withheld,
}

/// A delivered datagram's device reference, the end that sent it, whose `reclaim` returns it, and when that reclaim may.
struct Return<'a> {
    due: Due,
    sender: usize,
    /// Dropping the hold returns the reference.
    _hold: NicHold<'a>,
}

impl Return<'_> {
    fn returnable(&self, now: u64) -> bool {
        matches!(self.due, Due::At(due) if due <= now)
    }
}

/// One queued datagram: its copied header and inline bytes in order, a device reference for each retained piece, which delivery reads, its bytes at send, and the corruption delivery applies to its copy.
struct Entry<'a> {
    due: u64,
    /// The carried ordinal of the send this copy rides.
    ordinal: u64,
    pieces: Vec<Piece<'a>>,
    truncate: bool,
    corrupt: Option<Corruption>,
    sent: Vec<u8>,
}

enum Piece<'a> {
    Copied(Vec<u8>),
    Held(NicHold<'a>),
    /// A retained piece whose reference returned at send, read in place at delivery.
    Unheld(std::ptr::NonNull<u8>, usize),
}

impl Piece<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Copied(copied) => copied,
            Self::Held(hold) => hold.bytes(),
            // SAFETY: the arena outlives the link, the address came from a hold on its mapping, and no mutable view is live while the single-threaded test reads it; the bytes may have changed, which is what the negative control observes.
            Self::Unheld(addr, len) => unsafe { std::slice::from_raw_parts(addr.as_ptr(), *len) },
        }
    }
}

impl Entry<'_> {
    /// The datagram's bytes as the device reads them now.
    fn bytes(&self) -> Vec<u8> {
        self.pieces.iter().flat_map(Piece::bytes).copied().collect()
    }

    /// Bytes the link copied for this datagram.
    fn copied(&self) -> usize {
        self.pieces
            .iter()
            .map(|piece| match piece {
                Piece::Copied(bytes) => bytes.len(),
                Piece::Held(_) | Piece::Unheld(..) => 0,
            })
            .sum()
    }

    fn holds(&self) -> usize {
        self.pieces
            .iter()
            .filter(|piece| matches!(piece, Piece::Held(_)))
            .count()
    }

    /// Whether a retained piece's reference returned at send, under the premature-return control in force then.
    fn unheld(&self) -> bool {
        self.pieces
            .iter()
            .any(|piece| matches!(piece, Piece::Unheld(..)))
    }
}

/// Datagrams in flight toward one end.
struct Direction<'a> {
    queue: Vec<Entry<'a>>,
    last: Option<Vec<u8>>,
    faults: Faults,
    report: NetReport,
    /// Later datagrams the drawn burst still takes.
    run: u32,
    /// The resend keys of the last datagrams that reached the draws toward this end, newest last, `None` for one
    /// that decoded to no header.
    resend_keys: std::collections::VecDeque<Option<ResendKey>>,
}

/// The shared network state both ends and the test drive.
pub(crate) struct Net<'a> {
    /// Toward end 0 and toward end 1.
    directions: [Direction<'a>; 2],
    capacity: usize,
    max_len: usize,
    limits: LinkLimits,
    draws: Draws,
    actor: u16,
    /// The chooser incarnation the link's draws carry, once launched.
    incarnation: Option<u32>,
    now: u64,
    dead: [bool; 2],
    release: TxRelease,
    returns: Vec<Return<'a>>,
    rules: Chain,
    audit: Audit,
    /// Delivered copies the link corrupted or truncated, for the containment check.
    damaged: Vec<Damaged>,
    /// A damaged copy past the manifest's captures was left unkept.
    damaged_overflow: bool,
    /// The first draw the chooser refused.
    draw_error: Option<ChoiceError>,
    /// Messages the link carried, the next one's ordinal.
    carried: u64,
    /// Every datagram that reached its receiving end, delivered, truncated
    /// or missed at an empty ring, in order, at most the manifest's
    /// captures; a datagram a kill or a clear drops in flight never reaches
    /// it.
    deliveries: Vec<Delivery>,
    /// A delivery past the manifest's captures was left unlogged.
    deliveries_overflow: bool,
    /// The next send fails with no origin the harness can name.
    unattributed: bool,
}

impl<'a> Net<'a> {
    /// Launches the link as its actor's next chooser incarnation: its draws
    /// carry that incarnation, and the chooser refuses every earlier
    /// incarnation's draws from here.
    pub(crate) fn launch(&mut self) {
        self.incarnation = Some(self.draws.borrow_mut().launch(self.actor));
    }

    /// Advances the network clock to `turn`; datagrams due by then become receivable, and device references due by then become returnable on their sender's next `reclaim`.
    pub(crate) fn advance(&mut self, turn: u64) {
        self.now = self.now.max(turn);
    }

    /// Sets when delivered datagrams' device references return.
    pub(crate) fn set_tx_release(&mut self, release: TxRelease) {
        self.release = release;
    }

    /// Returns every device reference the network still holds for delivered datagrams.
    pub(crate) fn release_tx(&mut self) {
        self.returns.clear();
    }

    /// Device references the network holds: for queued datagrams and for delivered ones not yet returned.
    pub(crate) fn nic_held(&self) -> usize {
        let queued = self
            .directions
            .iter()
            .flat_map(|direction| &direction.queue);
        queued.map(Entry::holds).sum::<usize>() + self.returns.len()
    }

    /// Bytes the direction toward end `to` holds copied in flight, which
    /// the copy bound limits.
    pub(crate) fn copied(&self, to: usize) -> usize {
        self.directions[to].queue.iter().map(Entry::copied).sum()
    }

    /// Makes the `nth` withheld reference, in delivery order, returnable now, on its sender's next `reclaim`: the selected eligibility event that ends its charge.
    ///
    /// # Panics
    ///
    /// When fewer than `nth + 1` references are withheld.
    pub(crate) fn return_tx(&mut self, nth: usize) {
        let mut withheld = self
            .returns
            .iter_mut()
            .filter(|held| held.due == Due::Withheld);
        let held = withheld.nth(nth).expect("a withheld reference");
        held.due = Due::At(self.now);
    }

    /// Delivered references withheld until a selected [`return_tx`](Self::return_tx).
    pub(crate) fn withheld(&self) -> usize {
        self.returns
            .iter()
            .filter(|held| held.due == Due::Withheld)
            .count()
    }

    /// References `sender`'s next `reclaim` returns.
    pub(crate) fn reclaimable(&self, sender: usize) -> usize {
        let now = self.now;
        self.returns
            .iter()
            .filter(|held| held.sender == sender && held.returnable(now))
            .count()
    }

    /// The earliest turn after the network clock at which a delayed reference becomes returnable.
    pub(crate) fn next_return(&self) -> Option<u64> {
        let now = self.now;
        self.returns
            .iter()
            .filter_map(|held| match held.due {
                Due::At(due) if due > now => Some(due),
                Due::At(_) | Due::Withheld => None,
            })
            .min()
    }

    /// Bounds the link's copied bytes and retained transmit slots.
    pub(crate) fn set_limits(&mut self, limits: LinkLimits) {
        self.limits = limits;
    }

    /// Replaces the rule chain every later send runs.
    pub(crate) fn set_rules(&mut self, rules: Chain) {
        self.rules = rules;
    }

    /// The rule chain, with its captures.
    pub(crate) fn rules(&self) -> &Chain {
        &self.rules
    }

    /// The audited outcomes the link keeps: every one so far, less the
    /// passing records a caller retired through
    /// [`retire_audit`](Self::retire_audit).
    pub(crate) fn audit(&self) -> &Audit {
        &self.audit
    }

    /// Retires the passing audit records at or after `from`, which the
    /// caller has read; returns how many records remain. See
    /// [`Audit::retire`].
    pub(crate) fn retire_audit(&mut self, from: usize) -> usize {
        self.audit.retire(from)
    }

    /// Delivered copies the link corrupted or truncated, at most the manifest's captures.
    pub(crate) fn damaged(&self) -> &[Damaged] {
        &self.damaged
    }

    /// The ordered delivery log, and whether a delivery past the
    /// manifest's captures went unlogged, which leaves the log incomplete.
    pub(crate) fn deliveries(&self) -> (&[Delivery], bool) {
        (&self.deliveries, self.deliveries_overflow)
    }

    fn log(&mut self, toward: usize, ordinal: u64, bytes: (&[u8], usize), landed: Landed) {
        if self.deliveries.len() < MANIFEST.captures {
            self.deliveries
                .push(Delivery::of(toward, ordinal, bytes, landed));
        } else {
            self.deliveries_overflow = true;
        }
    }

    /// The first draw the chooser refused, a harness defect the run reports.
    pub(crate) fn draw_error(&self) -> Option<ChoiceError> {
        self.draw_error
    }

    pub(crate) fn take_draw_error(&mut self) -> Option<ChoiceError> {
        self.draw_error.take()
    }

    /// The link's judgment under the profile's `declared` reasons: the audit's failure first, then an inconclusive bound from the audit, the rule chain's captures or the damaged copies, else a pass. A refused draw reports apart, through [`draw_error`](Self::draw_error).
    pub(crate) fn verdict(&self, declared: &[Reason]) -> Verdict {
        let captures = match self.rules.overflow() {
            Some(bound) => Verdict::Inconclusive(bound),
            None => Verdict::Pass,
        };
        let damaged = if self.damaged_overflow {
            Verdict::Inconclusive(Bound::Damaged)
        } else {
            Verdict::Pass
        };
        self.audit.verdict(declared).then(captures).then(damaged)
    }

    /// Shortens the longest datagram the link takes.
    pub(crate) fn set_max_len(&mut self, max_len: usize) {
        self.max_len = max_len;
    }

    /// The next send fails with no origin the harness can name: a harness defect the audit fails.
    pub(crate) fn fail_unattributed(&mut self) {
        self.unattributed = true;
    }

    /// Records one outcome toward end `toward`: bumps its report counter, if it has one, and audits it with `class`.
    fn outcome(&mut self, toward: usize, class: Class, reason: Reason) {
        let report = &mut self.directions[toward].report;
        match reason {
            Reason::Lost
            | Reason::LostBurst
            | Reason::LostResend
            | Reason::RuleDrop
            | Reason::Isolated
            | Reason::DeadEnd => report.lost += 1,
            Reason::Full(_) => report.full += 1,
            Reason::Duplicated => report.duplicated += 1,
            Reason::Stale => report.stale += 1,
            Reason::Delayed => report.delayed += 1,
            Reason::Reordered => report.reordered += 1,
            Reason::Truncated => report.truncated += 1,
            Reason::CallFailed => report.errors += 1,
            Reason::WouldBlock => report.blocked += 1,
            Reason::Missed => report.missed += 1,
            Reason::Altered => report.altered += 1,
            Reason::Corrupted(_)
            | Reason::Inapplicable(_)
            | Reason::ForeignPeer
            | Reason::Oversize
            | Reason::NotHoldable
            | Reason::PrematureReturn
            | Reason::DeviceRefused(..)
            | Reason::DeviceInjected(_)
            | Reason::DeviceLost
            | Reason::DeviceOmitted(_)
            | Reason::DeviceFalseStopped
            | Reason::Unattributed => {}
        }
        let source = Source::Link {
            actor: self.actor,
            toward,
        };
        self.audit.note(class, reason, source);
    }

    /// A value below `bound` drawn for `draw` toward end `toward`, or `None` when the chooser refused it, which latches the link's draw error.
    ///
    /// # Panics
    ///
    /// Before the link launched: a [`network_later`] link carries traffic
    /// only once [`launch`](Self::launch) started its incarnation.
    fn draw(&mut self, draw: Draw, toward: usize, bound: u64) -> Option<u64> {
        let site = site(self.actor, draw, toward);
        let Some(incarnation) = self.incarnation else {
            panic!("a link draws only once its incarnation launched");
        };
        let drawn = self.draws.borrow_mut().bounded(site, incarnation, bound);
        drawn
            .inspect_err(|error| {
                self.draw_error.get_or_insert(*error);
            })
            .ok()
    }

    /// End `side` dies: its sends vanish, and datagrams queued toward it drop with their device references.
    pub(crate) fn kill(&mut self, side: usize) {
        self.dead[side] = true;
        self.directions[side].queue.clear();
    }

    /// Replaces the faults of the direction toward end `side`, ending any drawn burst there; the resend window
    /// stays.
    pub(crate) fn set_faults(&mut self, side: usize, faults: Faults) {
        let direction = &mut self.directions[side];
        direction.faults = faults;
        direction.run = 0;
    }

    /// A copy of the datagram at the back of the queue toward end `side`, the newest one while reordering is off, if any is in flight.
    pub(crate) fn peek(&self, side: usize) -> Option<Vec<u8>> {
        self.directions[side].queue.last().map(Entry::bytes)
    }

    /// Queues `bytes` toward end `side` as it stands, due now, carried as
    /// the next ordinal.
    pub(crate) fn inject(&mut self, side: usize, bytes: &[u8]) {
        let due = self.now;
        let ordinal = self.carried;
        self.carried += 1;
        self.directions[side].queue.push(Entry {
            due,
            ordinal,
            pieces: vec![Piece::Copied(bytes.to_vec())],
            truncate: false,
            corrupt: None,
            sent: bytes.to_vec(),
        });
    }

    /// Drops every datagram in flight toward end `side`.
    pub(crate) fn clear(&mut self, side: usize) {
        self.directions[side].queue.clear();
    }

    /// Keeps only the datagrams in flight toward end `side` for which `keep` holds, modelling a path that drops one kind of traffic.
    pub(crate) fn retain(&mut self, side: usize, mut keep: impl FnMut(&[u8]) -> bool) {
        self.directions[side]
            .queue
            .retain(|entry| keep(&entry.bytes()));
    }

    /// What the direction toward end `side` did.
    pub(crate) fn report(&self, side: usize) -> NetReport {
        self.directions[side].report
    }

    /// The carried ordinal the link's next datagram takes, so every datagram sent from here on carries this one or a
    /// later one.
    pub(crate) fn carried(&self) -> u64 {
        self.carried
    }

    pub(crate) fn pending(&self, side: usize) -> usize {
        self.directions[side].queue.len()
    }

    /// Datagrams toward end `side` due by the network clock, which a receive there can take.
    pub(crate) fn receivable(&self, side: usize) -> usize {
        let now = self.now;
        self.directions[side]
            .queue
            .iter()
            .filter(|entry| entry.due <= now)
            .count()
    }

    /// The earliest turn after the network clock at which a queued datagram falls due, toward either end.
    pub(crate) fn next_arrival(&self) -> Option<u64> {
        let now = self.now;
        self.directions
            .iter()
            .flat_map(|direction| &direction.queue)
            .map(|entry| entry.due)
            .filter(|&due| due > now)
            .min()
    }

    /// Whether a `percent` chance of `draw` toward end `toward` hit; a zero percentage draws nothing.
    fn chance(&mut self, draw: Draw, toward: usize, percent: u64) -> bool {
        percent > 0
            && self
                .draw(draw, toward, 100)
                .is_some_and(|drawn| drawn < percent)
    }

    /// Queues `datagram` toward end `to`: draws the duplicate fault, takes one datagram of a drawn burst or else draws
    /// the loss fault, draws the resend loss for a resend no earlier draw dropped, runs the rule chain once, draws a
    /// burst after a committed loss, draws the stale fault, reserves every entry, copied byte and transmit slot the kept copies need, then takes their device references. A datagram to or from a dead end vanishes before any draw. `Ok(false)` when a reservation fails, `Err` when a retained source could not be held, and either way the datagram holds no device reference.
    fn push(&mut self, to: usize, datagram: &Outgoing<'_, 'a>) -> Result<bool, ()> {
        if self.dead[to] || self.dead[1 - to] {
            self.outcome(to, Class::Injected, Reason::DeadEnd);
            return Ok(true);
        }
        let faults = self.directions[to].faults;
        let ordinal = self.carried;
        self.carried += 1;
        let mut base = Decision {
            duplicate: self.chance(Draw::Duplicate, to, faults.duplicate),
            ..Decision::default()
        };
        let direction = &mut self.directions[to];
        if direction.run > 0 {
            direction.run -= 1;
            base.drop = Some(Dropped::Burst);
        } else if self.chance(Draw::Loss, to, faults.loss) {
            base.drop = Some(Dropped::Fault);
        }
        let bytes: Vec<u8> = std::iter::once(datagram.header)
            .chain(datagram.payload.iter().map(Payload::bytes))
            .flatten()
            .copied()
            .collect();
        let message = Message::decode(self.actor, to, ordinal, &bytes);
        let key = message.header.as_ref().map(ResendKey::of);
        let keys = &mut self.directions[to].resend_keys;
        let resend =
            faults.resend_loss > 0 && base.drop.is_none() && key.is_some() && keys.contains(&key);
        if keys.len() == MANIFEST.captures {
            keys.pop_front();
        }
        keys.push_back(key);
        if resend && self.chance(Draw::Resend, to, faults.resend_loss) {
            base.drop = Some(Dropped::Resend);
        }
        // An empty chain leaves the base decision as drawn.
        let decision = if self.rules.is_empty() {
            base
        } else {
            self.rules.decide(&message, base)
        };
        if decision.drop == Some(Dropped::Fault) && faults.burst > 0 {
            self.directions[to].run = self
                .draw(Draw::Burst, to, u64::from(faults.burst) + 1)
                .map_or(0, |run| run as u32);
        }
        if let Some(dropped) = decision.drop {
            let reason = match dropped {
                Dropped::Fault => Reason::Lost,
                Dropped::Burst => Reason::LostBurst,
                Dropped::Resend => Reason::LostResend,
                Dropped::Rule(_) => Reason::RuleDrop,
                Dropped::Isolated(_) => Reason::Isolated,
            };
            self.outcome(to, Class::Injected, reason);
            return Ok(true);
        }
        let copies = 1 + usize::from(decision.duplicate);
        let stale = if self.chance(Draw::Stale, to, faults.stale) {
            self.directions[to].last.clone()
        } else {
            None
        };
        let stale_len = stale.as_ref().map(Vec::len);
        if let Some(bound) = self.reservation(to, datagram, copies, stale_len) {
            self.outcome(to, Class::Modeled, Reason::Full(bound));
            return Ok(false);
        }
        let mut kept = Vec::with_capacity(copies);
        for copy in 0..copies {
            let mut pieces = vec![Piece::Copied(datagram.header.to_vec())];
            for piece in datagram.payload {
                pieces.push(match piece {
                    Payload::Inline(bytes) => Piece::Copied(bytes.to_vec()),
                    Payload::Retained(source) => {
                        let Ok(hold) = source.hold() else {
                            // The original's reference fits or production sent an unholdable source; a duplicate's reference is the injected fault's own demand.
                            let class = if copy == 0 {
                                Class::Production
                            } else {
                                Class::Injected
                            };
                            self.outcome(to, class, Reason::NotHoldable);
                            return Err(());
                        };
                        if self.release == TxRelease::Premature {
                            self.outcome(to, Class::Containment, Reason::PrematureReturn);
                            Piece::Unheld(hold.device_addr(), hold.bytes().len())
                        } else {
                            Piece::Held(hold)
                        }
                    }
                });
            }
            kept.push(pieces);
        }
        if copies == 2 {
            self.outcome(to, Class::Injected, Reason::Duplicated);
        }
        for pieces in kept {
            self.enqueue(to, pieces, &decision, ordinal);
        }
        if let Some(old) = stale {
            self.outcome(to, Class::Injected, Reason::Stale);
            self.enqueue(to, vec![Piece::Copied(old)], &Decision::default(), ordinal);
        }
        Ok(true)
    }

    /// The bound `copies` copies of `datagram` and a stale replay of `stale` bytes, together, would pass toward end `to`, or `None` when the queue entries, copied bytes and transmit slots they need are all free.
    fn reservation(
        &self,
        to: usize,
        datagram: &Outgoing<'_, 'a>,
        copies: usize,
        stale: Option<usize>,
    ) -> Option<Bound> {
        let mut inline = datagram.header.len();
        let mut retained = 0;
        for piece in datagram.payload {
            match piece {
                Payload::Inline(bytes) => inline += bytes.len(),
                Payload::Retained(_) => retained += 1,
            }
        }
        let entries = copies + usize::from(stale.is_some());
        let bytes = copies * inline + stale.unwrap_or(0);
        let slots = if self.release == TxRelease::Premature {
            0
        } else {
            copies * retained
        };
        let direction = &self.directions[to];
        let in_flight: usize = direction.queue.iter().map(Entry::copied).sum();
        if direction.queue.len() + entries > self.capacity {
            Some(Bound::Entries)
        } else if in_flight.saturating_add(bytes) > self.limits.copy_bytes {
            Some(Bound::CopyBytes)
        } else if self.nic_held().saturating_add(slots) > self.limits.tx_slots {
            Some(Bound::TxSlots)
        } else {
            None
        }
    }

    /// Queues one copy toward end `to` of the send carried as `ordinal`, its delay, truncation and position set by `decision` where the rules set them and drawn otherwise; a reordered copy goes ahead of every queued one.
    fn enqueue(&mut self, to: usize, pieces: Vec<Piece<'a>>, decision: &Decision, ordinal: u64) {
        let faults = self.directions[to].faults;
        let delay = match decision.delay {
            Some(turns) => turns,
            None if faults.delay > 0 => self
                .draw(Draw::Delay, to, faults.delay.saturating_add(1))
                .unwrap_or(0),
            None => 0,
        };
        let due = self.now.saturating_add(delay);
        let truncate = match decision.truncate {
            Some(truncate) => truncate,
            None => self.chance(Draw::Truncate, to, faults.truncate),
        };
        let len = self.directions[to].queue.len();
        let at = match decision.reorder {
            Some(true) => 0,
            Some(false) => len,
            None if len > 0 && self.chance(Draw::Reorder, to, faults.reorder) => self
                .draw(Draw::ReorderAt, to, len as u64 + 1)
                .map_or(len, |at| at as usize),
            None => len,
        };
        if at != len {
            self.outcome(to, Class::Injected, Reason::Reordered);
        }
        if due > self.now {
            self.outcome(to, Class::Injected, Reason::Delayed);
        }
        let sent = pieces.iter().flat_map(Piece::bytes).copied().collect();
        self.directions[to].queue.insert(
            at,
            Entry {
                due,
                ordinal,
                pieces,
                truncate,
                corrupt: decision.corrupt,
                sent,
            },
        );
    }

    /// The queue position of the first datagram due toward end `side`.
    fn first_due(&self, side: usize) -> Option<usize> {
        let now = self.now;
        self.directions[side]
            .queue
            .iter()
            .position(|entry| entry.due <= now)
    }

    /// Drops the datagram at `at` toward end `side`, which found no posted buffer.
    fn miss(&mut self, side: usize, at: usize) {
        let entry = self.directions[side].queue.remove(at);
        self.log(side, entry.ordinal, (&entry.bytes(), 0), Landed::Missed);
        self.outcome(side, Class::Modeled, Reason::Missed);
    }

    /// Writes the datagram at `at` toward end `side` into `posted`, a buffer
    /// of `pool`, returning the lease and whether it was truncated.
    fn deliver<'p>(
        &mut self,
        side: usize,
        at: usize,
        posted: RxPosted<'a>,
        pool: &'p PacketPool<'a>,
    ) -> (PacketLease<'p>, bool) {
        assert!(
            pool.holds(&posted),
            "a ring posting completes through the pool that posted it"
        );
        let entry = self.directions[side].queue.remove(at);
        // The device reads the held pieces now, before their references return.
        let read = entry.bytes();
        if read != entry.sent {
            // Classification uses the release mode recorded by the pieces at send, even if the mode changes before delivery.
            let class = if entry.unheld() {
                Class::Containment
            } else {
                Class::Production
            };
            self.outcome(side, class, Reason::Altered);
        }
        let mut bytes = read.clone();
        // A truncating fault delivers the datagram grown past the buffer, so the buffer keeps its first `capacity` bytes.
        let layout = pool.layout();
        let capacity = layout.data_room;
        let kept = bytes.len().min(capacity);
        let truncated = entry.truncate || bytes.len() > capacity;
        let len = if truncated { capacity } else { kept };
        let mut corrupt = None;
        if let Some(class) = entry.corrupt {
            let frame = super::rules::frame_of(&bytes[..kept]).len();
            if class.apply(&mut bytes[..frame]) {
                let origin = if class.layer().is_some() {
                    Class::Injected
                } else {
                    Class::Containment
                };
                self.outcome(side, origin, Reason::Corrupted(class));
                corrupt = Some(class);
            } else {
                // A corruption whose byte lies past the frame the rules read, the delivered bytes of a lone datagram or a packed datagram's first frame, changed nothing: a harness defect, and this corruption damaged no copy.
                self.outcome(side, Class::Harness, Reason::Inapplicable(class));
            }
        }
        // SAFETY: the posted buffer, whichever call posted it, is the device's alone until `received`; it belongs to `pool`, checked above, so `len <= capacity` keeps the copy and the zero fill of the grown tail inside its data room.
        unsafe {
            let room = posted.device_addr().add(layout.data_offset).as_ptr();
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), room, kept);
            std::ptr::write_bytes(room.add(kept), 0, len - kept);
        }
        // SAFETY: this device finished writing the posted buffer above.
        let lease = unsafe { pool.received(posted, len) };
        self.directions[side].report.delivered += 1;
        if truncated {
            // A truncation fault is injected; a datagram longer than the receive buffer is the model's bound.
            let class = if entry.truncate {
                Class::Injected
            } else {
                Class::Modeled
            };
            self.outcome(side, class, Reason::Truncated);
        }
        let landed = if truncated {
            Landed::Truncated
        } else {
            Landed::Delivered
        };
        self.log(side, entry.ordinal, (&bytes[..kept], len - kept), landed);
        if truncated || corrupt.is_some() {
            if self.damaged.len() < MANIFEST.captures {
                self.damaged.push(Damaged {
                    corruption: corrupt,
                    truncated,
                    toward: side,
                    bytes: bytes[..len.min(bytes.len())].to_vec(),
                });
            } else {
                self.damaged_overflow = true;
            }
        }
        // A stale replay repeats the datagram as the device read it at delivery, before any corruption.
        self.directions[side].last = Some(read);
        for piece in entry.pieces {
            if let Piece::Held(hold) = piece {
                let due = match self.release {
                    TxRelease::AtDelivery | TxRelease::Premature => continue,
                    TxRelease::Delayed(turns) => {
                        let delay = self
                            .draw(Draw::Release, side, turns.saturating_add(1))
                            .unwrap_or(0);
                        Due::At(self.now.saturating_add(delay))
                    }
                    TxRelease::Withheld => Due::Withheld,
                };
                self.returns.push(Return {
                    due,
                    sender: 1 - side,
                    _hold: hold,
                });
            }
        }
        (lease, truncated)
    }
}

/// One end of the network.
pub(crate) struct LinkEnd<'a> {
    net: Rc<RefCell<Net<'a>>>,
    side: usize,
    closed: bool,
    /// Receive buffers this end keeps posted across calls; zero posts one per delivery.
    ring: usize,
    posted: Vec<RxPosted<'a>>,
}

impl Drop for LinkEnd<'_> {
    fn drop(&mut self) {
        for posted in self.posted.drain(..) {
            // SAFETY: the link writes a posted buffer only during a receive call, so none is being written now.
            unsafe { posted.unpost() };
        }
    }
}

/// A clean network of `capacity` datagrams per direction, each at most `max_len` bytes.
pub(crate) fn link<'a>(capacity: usize, max_len: usize) -> (LinkEnd<'a>, LinkEnd<'a>) {
    let (a, b, _) = network(capacity, max_len, 0, [Faults::default(); 2]);
    (a, b)
}

/// A network with `faults[side]` on the direction toward end `side`, its schedule drawn by its own chooser from root `seed`, and a handle to its clock and state.
pub(crate) fn network<'a>(
    capacity: usize,
    max_len: usize,
    seed: u64,
    faults: [Faults; 2],
) -> (LinkEnd<'a>, LinkEnd<'a>, Rc<RefCell<Net<'a>>>) {
    let draws = Rc::new(RefCell::new(Chooser::record(seed, &sites(0))));
    network_drawn(capacity, max_len, faults, (&draws, 0))
}

/// A network with `faults[side]` on the direction toward end `side` whose every fault is a decision of `draws` at the sites of link `actor`, launched as that actor's next incarnation, and a handle to its clock and state.
pub(crate) fn network_drawn<'a>(
    capacity: usize,
    max_len: usize,
    faults: [Faults; 2],
    (draws, actor): (&Draws, u16),
) -> (LinkEnd<'a>, LinkEnd<'a>, Rc<RefCell<Net<'a>>>) {
    let (near, far, net) = network_later(capacity, max_len, faults, (draws, actor));
    net.borrow_mut().launch();
    (near, far, net)
}

/// [`network_drawn`] for a later incarnation of link `actor`, built while
/// an earlier incarnation still draws: the chooser goes on admitting the
/// earlier incarnation's draws until [`Net::launch`] starts this one.
pub(crate) fn network_later<'a>(
    capacity: usize,
    max_len: usize,
    faults: [Faults; 2],
    (draws, actor): (&Draws, u16),
) -> (LinkEnd<'a>, LinkEnd<'a>, Rc<RefCell<Net<'a>>>) {
    let direction = |faults| Direction {
        queue: Vec::with_capacity(capacity * 3),
        last: None,
        faults,
        report: NetReport::default(),
        run: 0,
        resend_keys: std::collections::VecDeque::new(),
    };
    let net = Rc::new(RefCell::new(Net {
        directions: [direction(faults[0]), direction(faults[1])],
        capacity,
        max_len,
        limits: UNBOUNDED,
        draws: Rc::clone(draws),
        actor,
        incarnation: None,
        now: 0,
        dead: [false; 2],
        release: TxRelease::AtDelivery,
        returns: Vec::new(),
        rules: Chain::default(),
        audit: Audit::new(MANIFEST.records),
        damaged: Vec::new(),
        damaged_overflow: false,
        draw_error: None,
        carried: 0,
        deliveries: Vec::new(),
        deliveries_overflow: false,
        unattributed: false,
    }));
    (
        LinkEnd {
            net: Rc::clone(&net),
            side: 0,
            closed: false,
            ring: 0,
            posted: Vec::new(),
        },
        LinkEnd {
            net: Rc::clone(&net),
            side: 1,
            closed: false,
            ring: 0,
            posted: Vec::new(),
        },
        net,
    )
}

impl<'a> LinkEnd<'a> {
    /// Another end on this end's side of the link, as a replacement
    /// endpoint at the same address: whichever end receives first takes
    /// what arrives toward the side.
    pub(crate) fn rejoin(&self) -> LinkEnd<'a> {
        LinkEnd {
            net: Rc::clone(&self.net),
            side: self.side,
            closed: false,
            ring: 0,
            posted: Vec::new(),
        }
    }
}

impl LinkEnd<'_> {
    pub(crate) fn pending(&self) -> usize {
        self.net.borrow().pending(self.side)
    }

    pub(crate) fn close(&mut self) {
        self.closed = true;
    }

    /// Keeps `ring` receive buffers posted across calls, as a device ring does.
    pub(crate) fn set_ring(&mut self, ring: usize) {
        self.ring = ring;
        self.posted.reserve(ring);
    }

    /// Draws this end's call fault: `Err` for a failing call, `Ok(true)` for one that would block.
    fn call_fault(&self, toward: usize) -> Result<bool, DatagramError> {
        let mut net = self.net.borrow_mut();
        let faults = net.directions[toward].faults;
        if net.chance(Draw::Error, toward, faults.error) {
            net.outcome(toward, Class::Injected, Reason::CallFailed);
            return Err(DatagramError::Failed {
                code: Some(libc::EIO),
            });
        }
        let blocked = net.chance(Draw::WouldBlock, toward, faults.would_block);
        if blocked {
            net.outcome(toward, Class::Injected, Reason::WouldBlock);
        }
        Ok(blocked)
    }

    /// Audits a production-origin refusal toward end `toward`.
    fn refused(&self, refusal: Refusal, toward: usize) {
        self.net
            .borrow_mut()
            .outcome(toward, Class::Production, refusal.reason());
    }
}

/// A datagram the link refuses before any draw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// A peer other than 0.
    ForeignPeer,
    /// Longer than the link's maximum.
    Oversize,
}

impl Refusal {
    /// The error the send reports.
    fn code(self) -> Option<i32> {
        match self {
            Self::ForeignPeer => None,
            Self::Oversize => Some(libc::EMSGSIZE),
        }
    }

    fn reason(self) -> Reason {
        match self {
            Self::ForeignPeer => Reason::ForeignPeer,
            Self::Oversize => Reason::Oversize,
        }
    }
}

/// Why the link refuses `datagram`, if it does.
fn refusal(datagram: &Outgoing<'_, '_>, max_len: usize) -> Option<Refusal> {
    if datagram.peer != PeerId(0) {
        Some(Refusal::ForeignPeer)
    } else if datagram.len() > max_len {
        Some(Refusal::Oversize)
    } else {
        None
    }
}

impl<'a> Datagrams<'a> for LinkEnd<'a> {
    fn receive<'p>(
        &mut self,
        pool: &'p PacketPool<'a>,
        into: &mut [Option<PacketLease<'p>>],
        meta: &mut [Received],
    ) -> Result<usize, DatagramError> {
        if self.closed {
            return Err(DatagramError::Closed);
        }
        if into.is_empty() || meta.is_empty() {
            return Ok(0);
        }
        crate::instrument::unmeasured(|| {
            if self.call_fault(self.side)? {
                return Ok(0);
            }
            Ok(self.deliver(pool, into, meta))
        })
    }

    fn send(&mut self, batch: &[Outgoing<'_, 'a>]) -> Result<usize, DatagramError> {
        crate::instrument::unmeasured(|| self.transmit(batch))
    }

    fn rx_ring(&self) -> u32 {
        self.ring as u32
    }

    fn reclaim(&mut self) {
        let side = self.side;
        crate::instrument::unmeasured(|| {
            let mut net = self.net.borrow_mut();
            let now = net.now;
            net.returns
                .retain(|held| held.sender != side || !held.returnable(now));
        });
    }
}

impl<'a> LinkEnd<'a> {
    fn deliver<'p>(
        &mut self,
        pool: &'p PacketPool<'a>,
        into: &mut [Option<PacketLease<'p>>],
        meta: &mut [Received],
    ) -> usize {
        self.refill(pool);
        let mut net = self.net.borrow_mut();
        let mut count = 0;
        for (slot, meta) in into.iter_mut().zip(meta.iter_mut()) {
            let Some(at) = net.first_due(self.side) else {
                break;
            };
            let posted = if self.ring > 0 {
                let Some(posted) = self.posted.pop() else {
                    net.miss(self.side, at);
                    continue;
                };
                posted
            } else {
                let Ok(posted) = pool.post() else {
                    break;
                };
                posted
            };
            let (lease, truncated) = net.deliver(self.side, at, posted, pool);
            *slot = Some(lease);
            *meta = Received {
                peer: Some(PeerId(0)),
                truncated,
            };
            count += 1;
        }
        drop(net);
        self.refill(pool);
        count
    }

    /// Posts free buffers of `pool` until the ring is full, as a device refills every free entry at once.
    fn refill(&mut self, pool: &PacketPool<'a>) {
        while self.posted.len() < self.ring {
            let Ok(posted) = pool.post() else {
                break;
            };
            self.posted.push(posted);
        }
    }

    fn transmit(&mut self, batch: &[Outgoing<'_, 'a>]) -> Result<usize, DatagramError> {
        if self.closed {
            return Err(DatagramError::Closed);
        }
        let toward = 1 - self.side;
        let Some(first) = batch.first() else {
            return Ok(0);
        };
        let max_len = self.net.borrow().max_len.min(super::datagram::MAX_DATAGRAM);
        if std::mem::take(&mut self.net.borrow_mut().unattributed) {
            self.net
                .borrow_mut()
                .outcome(toward, Class::Harness, Reason::Unattributed);
            return Err(DatagramError::Failed { code: None });
        }
        // A refused leading datagram fails the call before any call fault is drawn, and a refused later one ends the accepted prefix.
        if let Some(refused) = refusal(first, max_len) {
            self.refused(refused, toward);
            return Err(DatagramError::Failed {
                code: refused.code(),
            });
        }
        if self.call_fault(toward)? {
            return Ok(0);
        }
        let mut net = self.net.borrow_mut();
        let mut count = 0;
        for datagram in batch {
            if let Some(refused) = refusal(datagram, max_len) {
                drop(net);
                self.refused(refused, toward);
                break;
            }
            match net.push(toward, datagram) {
                Ok(true) => count += 1,
                Ok(false) => break,
                Err(()) if count == 0 => {
                    return Err(DatagramError::Failed {
                        code: Some(libc::ESTALE),
                    });
                }
                Err(()) => break,
            }
        }
        Ok(count)
    }
}
