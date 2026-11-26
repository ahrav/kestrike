//! The mixed and cluster worlds as worker runs: the events they emit
//! between actions, their canonical encodings, and the run of one manifest
//! into a bundle.
//!
//! Every executed action emits an `ACT` event, and a witnessed one a
//! `WITNESS` event. In the mixed world every upload action emits a `PUT`
//! event naming its kind, attempt, session, fragment, the first 16 bytes
//! of the SHA-256 of the bytes it supplied, the time a deferral holds the
//! supplier back, and its outcome code. After any turn that changed it, the upload's state
//! emits an `UPLOAD` event: its attempt, fill serial, receipt base and
//! grant, the source slots a device holds, its collected outcome and
//! whether the owner binds its key. Each new link audit record emits an
//! `AUDIT` event, and each new capture of a link rule chain's taps a `RULE`
//! event with the decision the tap saw. The world's first failure emits a
//! `FAILURE` event, which the recorder takes as its violation and flushes
//! with a checkpoint before any later record, when it names a broken
//! obligation; an unsuccessful, truncated or inconclusive observation emits
//! an `OBSERVED` event instead. A cluster run's teardown and minimum
//! checks record their failure after the controller returns. An
//! unsuccessful, truncated or inconclusive check emits its `OBSERVED`
//! event after the coverage event. A run ended by a refused entropy
//! draw records an `ENTROPY` event
//! naming the draw's site, incarnation and error. After the controller
//! returns, the run offers a final `STOP` event naming how the controller
//! stopped and, for a mixed or cluster run, the stopped boundaries it
//! checked and its owner and client counts.
//! `PUT`, `UPLOAD` and `RULE` events occur only in mixed runs; a cluster
//! run offers its `COVERAGE` event before its stop event. A recorder that
//! a cap or a defect closed drops the stop event, and a panic unwinds
//! before the run emits it; a reader treats a bundle without one as
//! holding no stop and no composition. A violating run offers an
//! `IDENTITY` event, the versioned failure identity a reduction keeps,
//! after its violation record and before its coverage and stop events. A
//! mixed or cluster turn whose action collected a GET or PUT result
//! records it as its observation, which [`Collected`] lays out; a recovery
//! turn records none.

use std::cell::RefCell;
use std::io::Write;

use sha2::{Digest, Sha256};

use crate::oracle::Obligation;
use crate::sim::action::{ActionKind, Profile};
use crate::sim::choice::{Candidate, ChoiceError, Chooser};
use crate::sim::entropy::DrawRefusal;
use crate::sim::manifest::Manifest;
use crate::sim::recovery::{Mismatch, RecordError, Recovery, recovery_profile};
use crate::sim::trace::{
    Closed, Event, Field, Infrastructure, Loaded, Outcome, PAYLOAD, Recorder, Terminal, Work,
    admitted, bit,
};
use crate::sim::turn::{Defect, End, Hook, Limits, Turn};

use super::super::audit::{Class, Reason, Record, Source, Verdict};
use super::super::frame::{Kind, parse};
use super::super::link::LinkLimits;
use super::super::observe::Failure;
use super::super::rules::{Capture, Dropped, MANIFEST};
use super::{
    Mixed, Plan, Plant, QUIET, UPLOAD_PLAN, WorldKind, coverage, exactly_read, healed, mixed_run,
    published_then_read, put_kind, refused_read, upload_profile, witnessed,
};

/// Event kinds of a run's bundle; `PUT`, `UPLOAD` and `RULE` occur only
/// in mixed runs.
pub(crate) const ACT: u8 = 1;
pub(crate) const WITNESS: u8 = 2;
pub(crate) const PUT: u8 = 3;
pub(crate) const UPLOAD: u8 = 4;
pub(crate) const AUDIT: u8 = 5;
pub(crate) const FAILURE: u8 = 6;
pub(crate) const RULE: u8 = 7;
pub(crate) const OBSERVED: u8 = 8;
/// The refused entropy draw that ended the run: the actor and site as
/// little-endian `u16`s, the incarnation as a little-endian `u32`, then the
/// chooser's error as debug text, truncated to the remaining
/// `PAYLOAD - 8` bytes and zero-padded.
pub(crate) const ENTROPY: u8 = 11;
/// How the run stopped, the last event a run offers once its controller
/// returns, absent where the recorder closed first: the end's class (1 the
/// goal, 2 a limit, 3 a defect, 4 a hook that halted the run), its detail
/// (a limit's code: 1 total turns, 2 same-time turns, 3 turns without
/// progress, 4 quiescence; a defect's: 1 a refused decision, 2 a refused
/// entropy draw, 3 a due time at or before the present; 0 for a halted
/// run), 1 when the composition follows, else 0, then the stopped
/// boundaries the run checked as a little-endian `u64` and its owner and
/// client counts as little-endian `u16`s. A mixed run records its
/// composition and a cluster run its drawn owner count and two clients; a
/// recovery run records none and leaves those fields zero.
pub(crate) const STOP: u8 = 12;

/// Every event kind a bundle holds. A reader selects events by kind, so
/// each kind is distinct from every other.
const KINDS: &[u8] = &[
    ACT,
    WITNESS,
    PUT,
    UPLOAD,
    AUDIT,
    FAILURE,
    RULE,
    OBSERVED,
    crate::sim::ledger::LEDGER,
    super::super::witness::OBSERVATION,
    ENTROPY,
    STOP,
    super::cluster::COVERAGE,
    super::cluster::WINDOW,
    IDENTITY,
];

const fn distinct(kinds: &[u8]) -> bool {
    let mut at = 0;
    while at < kinds.len() {
        let mut next = at + 1;
        while next < kinds.len() {
            if kinds[at] == kinds[next] {
                return false;
            }
            next += 1;
        }
        at += 1;
    }
    true
}

const _: () = assert!(
    distinct(KINDS),
    "a reader that selects events by kind mistakes one event for another"
);

/// The world a mixed or cluster run composes, for its [`STOP`] event:
/// stopped boundaries checked, owners and clients.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Composed {
    pub(crate) checked: u64,
    pub(crate) owners: u16,
    pub(crate) clients: u16,
}

/// A mixed run's owner and client counts.
pub(crate) const TOPOLOGY: (u16, u16) = (1, 2);

/// The owner and client counts `plan`'s mixed run composes: [`TOPOLOGY`],
/// or two owners with two clients each when the plan runs a peer owner.
fn composition(plan: &Plan) -> (u16, u16) {
    let owners = TOPOLOGY.0 + u16::from(plan.peer_owner);
    (owners, TOPOLOGY.1 * owners)
}

/// What a bundle's events say a run observed, beside its terminal and work.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Observed {
    /// The stop event's end class and detail, when the bundle records one.
    pub(crate) stop: Option<(u8, u8)>,
    /// The composition the stop event records.
    pub(crate) composed: Option<Composed>,
    /// Executed workload actions: `ACT` events.
    pub(crate) operations: u64,
    /// Witnessed actions: `WITNESS` events.
    pub(crate) witnesses: u64,
    /// Link faults the run injected: `AUDIT` events whose record class is
    /// `Injected`. Other audit classes and device faults are excluded.
    pub(crate) faults: u64,
    /// A cluster run's drawn owner count, key count and hot key, and each
    /// count it reached, from its coverage event.
    pub(crate) coverage: Option<(
        super::cluster::Topology,
        [u32; super::cluster::Reached::COUNT],
    )>,
    /// Unsuccessful, truncated or inconclusive oracle observations:
    /// `OBSERVED` events.
    pub(crate) observations: u64,
}

/// Each [`STOP`] class and detail code with the text the summary names it
/// by.
pub(crate) const STOPS: [((u8, u8), &str); 9] = [
    ((1, 0), "goal"),
    ((2, 1), "limit turns"),
    ((2, 2), "limit same_time"),
    ((2, 3), "limit no_progress"),
    ((2, 4), "quiescent"),
    ((3, 1), "defect choice"),
    ((3, 2), "defect entropy"),
    ((3, 3), "defect due"),
    ((4, 0), "halted"),
];

impl Observed {
    /// How the run stopped, as the summary names it.
    pub(crate) fn stop_text(&self) -> &'static str {
        self.stop.map_or("unavailable", stop_name)
    }
}

/// The summary's name of the stop whose class and detail are `code`.
pub(crate) fn stop_name(code: (u8, u8)) -> &'static str {
    STOPS
        .iter()
        .find(|(known, _)| *known == code)
        .map_or("unknown", |(_, text)| text)
}

/// What a bundle's `events` record of its run.
pub(crate) fn observed(events: &[Event]) -> Observed {
    let mut seen = Observed::default();
    for event in events {
        let p = &event.payload;
        match event.kind {
            STOP => {
                seen.stop = Some((p[0], p[1]));
                seen.composed = (p[2] == 1).then(|| Composed {
                    checked: u64::from_le_bytes(p[3..11].try_into().expect("eight bytes")),
                    owners: u16::from_le_bytes([p[11], p[12]]),
                    clients: u16::from_le_bytes([p[13], p[14]]),
                });
            }
            ACT => seen.operations += 1,
            WITNESS => seen.witnesses += 1,
            AUDIT if p[1] == Class::Injected as u8 => seen.faults += 1,
            OBSERVED => seen.observations += 1,
            super::cluster::COVERAGE => seen.coverage = Some(super::cluster::coverage_of(event)),
            _ => {}
        }
    }
    seen
}

/// The rule text of the first unsuccessful check `loaded` records: the
/// rule bytes of its first `OBSERVED` event whose failure code names an
/// unsuccessful check, at most the payload less its three code bytes.
/// `None` when the bundle records none, the recorded length passes the
/// payload, or the text holds a byte outside printable ASCII, so the text
/// stays within one summary line.
pub(crate) fn unsuccessful_rule(loaded: &Loaded) -> Option<String> {
    let code = &loaded
        .events
        .iter()
        .find(|event| event.kind == OBSERVED && event.payload[0] & !TRUNCATED == UNSUCCESSFUL)?
        .payload;
    let rule = std::str::from_utf8(code.get(3..3 + usize::from(code[2]))?).ok()?;
    rule.bytes()
        .all(|byte| (b' '..=b'~').contains(&byte))
        .then(|| rule.to_owned())
}

/// The [`STOP`] event for a run that ended as `end` over `composed`.
pub(crate) fn stop_event(end: End, composed: Option<Composed>) -> Event {
    use crate::sim::turn::Limit;
    let (class, detail) = match end {
        End::Done => (1, 0),
        End::Inconclusive(limit) => (
            2,
            match limit {
                Limit::Total => 1,
                Limit::SameTime => 2,
                Limit::NoProgress => 3,
                Limit::Quiescent => 4,
            },
        ),
        End::Defect(defect) => (
            3,
            match defect {
                Defect::Choice(_) => 1,
                Defect::Entropy(_) => 2,
                Defect::Due { .. } => 3,
            },
        ),
        End::Halted => (4, 0),
    };
    let present = composed.is_some();
    let composed = composed.unwrap_or_default();
    event(
        STOP,
        &[
            &[class, detail, u8::from(present)],
            &composed.checked.to_le_bytes(),
            &composed.owners.to_le_bytes(),
            &composed.clients.to_le_bytes(),
        ],
    )
}

#[cfg(test)]
pub(crate) mod tests;

#[cfg(test)]
pub(crate) mod chaos_tests;

/// How far the world's emission has reached.
#[derive(Debug, Default)]
pub(super) struct Emitted {
    acts: usize,
    audits: [usize; 4],
    captures: [usize; 4],
    upload: Option<[u8; PAYLOAD]>,
    failure: bool,
    /// Upload actions emitted over the run.
    pub(super) puts: u64,
}

impl Emitted {
    /// Starts the scripted owner's link cursors over for a relaunched
    /// incarnation's links, whose audits and captures begin empty; a peer's
    /// cursors stay.
    pub(super) fn relaunched(&mut self) {
        self.audits[..2].fill(0);
        self.captures[..2].fill(0);
    }
}

fn event(kind: u8, fields: &[&[u8]]) -> Event {
    let mut payload = [0; PAYLOAD];
    let mut at = 0;
    for field in fields {
        payload[at..at + field.len()].copy_from_slice(field);
        at += field.len();
    }
    Event { kind, payload }
}

/// The [`ENTROPY`] event recording `refusal`.
pub(super) fn entropy_event(refusal: DrawRefusal) -> Event {
    let error = format!("{:?}", refusal.error);
    let at = (PAYLOAD - 8).min(error.len());
    event(
        ENTROPY,
        &[
            &refusal.site.actor.to_le_bytes(),
            &refusal.site.site.to_le_bytes(),
            &refusal.incarnation.to_le_bytes(),
            &error.as_bytes()[..at],
        ],
    )
}

/// The first 16 bytes of the SHA-256 of `bytes`.
fn content(bytes: &[u8]) -> [u8; 16] {
    Sha256::digest(bytes)[..16]
        .try_into()
        .expect("sixteen bytes")
}

/// A reason's canonical code: its variant, then the codes of what it
/// carries.
pub(super) fn reason_code(reason: Reason) -> [u8; 3] {
    match reason {
        Reason::Lost => [1, 0, 0],
        Reason::RuleDrop => [2, 0, 0],
        Reason::Isolated => [3, 0, 0],
        Reason::Duplicated => [4, 0, 0],
        Reason::Stale => [5, 0, 0],
        Reason::Delayed => [6, 0, 0],
        Reason::Reordered => [7, 0, 0],
        Reason::Truncated => [8, 0, 0],
        Reason::Corrupted(corruption) => [9, corruption as u8, 0],
        Reason::Inapplicable(corruption) => [10, corruption as u8, 0],
        Reason::WouldBlock => [11, 0, 0],
        Reason::CallFailed => [12, 0, 0],
        Reason::DeadEnd => [13, 0, 0],
        Reason::Missed => [14, 0, 0],
        Reason::Full(bound) => [15, bound as u8, 0],
        Reason::ForeignPeer => [16, 0, 0],
        Reason::Oversize => [17, 0, 0],
        Reason::NotHoldable => [18, 0, 0],
        Reason::PrematureReturn => [19, 0, 0],
        Reason::Altered => [20, 0, 0],
        Reason::DeviceRefused(origin, refusal) => [21, origin as u8, refusal as u8],
        Reason::DeviceInjected(injection) => [22, injection as u8, 0],
        Reason::DeviceLost => [23, 0, 0],
        Reason::Unattributed => [24, 0, 0],
        Reason::DeviceOmitted(omission) => [25, omission as u8, 0],
        Reason::DeviceFalseStopped => [26, 0, 0],
        Reason::LostBurst => [27, 0, 0],
        Reason::LostResend => [28, 0, 0],
    }
}

/// Whether `failure` names a broken obligation: a violation, or an oracle
/// verdict that is one.
fn violates(failure: &Failure) -> bool {
    match failure {
        Failure::Violation(..) => true,
        Failure::Oracle(verdict) => verdict.violated().is_some(),
        Failure::Unsuccessful(_) | Failure::Truncated(_) => false,
    }
}

/// The identity event of a failure: its versioned failure identity, which
/// a reduction keeps. The payload is [`IDENTITY_VERSION`], the violation
/// code's variant, the obligation plus one (0 for none), the audit class
/// plus one (0 for none), the [`Site`] the failure surfaced at, the hashed
/// text's length as a little-endian `u16` saturating at `u16::MAX`, then
/// the SHA-256 of the full rule text or of the encoded audit class, reason
/// and source. Two rules that share a prefix the violation record
/// truncates, and one rule raised at two sites, are distinct identities.
pub(crate) const IDENTITY: u8 = 15;

/// The encoding version [`IDENTITY`] events carry. A change to the payload
/// layout, a tag's meaning, the hash or the hashed text's encoding takes a
/// new version, so identities of two encodings differ in their first byte.
pub(crate) const IDENTITY_VERSION: u8 = 2;

/// Where a run's failure surfaced, part of its identity: one rule raised
/// by a check while the run executes and by the check its settlement runs
/// are two failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Site {
    Run = 1,
    Settled = 2,
}

const UNSUCCESSFUL: u8 = 3;
const TRUNCATED: u8 = 0x80;

fn failure_parts(failure: &Failure) -> (u8, Option<Obligation>, &'static str) {
    match failure {
        Failure::Violation(obligation, rule) => (1, Some(*obligation), rule),
        Failure::Oracle(verdict) => match verdict.violated() {
            Some((obligation, rule)) => (2, Some(obligation), rule),
            None => (2, None, "inconclusive"),
        },
        Failure::Unsuccessful(rule) => (UNSUCCESSFUL, None, rule),
        Failure::Truncated(inner) => failure_parts(inner),
    }
}

/// The [`IDENTITY`] event of `failure` surfacing at `site`. `failure`
/// names a broken obligation, as [`violates`] decides: the identity omits
/// the truncation bit the violation record carries, so it names only a
/// failure that a judgment can keep as a violation.
pub(crate) fn identity_event(failure: &Failure, site: Site) -> Event {
    debug_assert!(
        violates(failure),
        "an identity names a broken obligation: {failure:?}"
    );
    let (variant, obligation, rule) = failure_parts(failure);
    identity_of((variant, obligation, None, site), rule.as_bytes())
}

fn audit_identity(record: &Record) -> Event {
    let [reason, first, second] = reason_code(record.reason);
    let (place, actor, toward) = source_parts(record.source);
    let toward = toward as u64;
    let mut code = [0; 15];
    code[..5].copy_from_slice(&[record.class as u8, reason, first, second, place]);
    code[5..7].copy_from_slice(&actor.to_le_bytes());
    code[7..].copy_from_slice(&toward.to_le_bytes());
    identity_of((4, None, Some(record.class), Site::Settled), &code)
}

fn identity_of(
    (variant, obligation, class, site): (u8, Option<Obligation>, Option<Class>, Site),
    text: &[u8],
) -> Event {
    let length = u16::try_from(text.len()).unwrap_or(u16::MAX).to_le_bytes();
    event(
        IDENTITY,
        &[
            &[
                IDENTITY_VERSION,
                variant,
                obligation.map_or(0, obligation_code),
                class.map_or(0, |class| class as u8 + 1),
                site as u8,
            ],
            &length,
            &Sha256::digest(text),
        ],
    )
}

/// The evidence a violating run's violation record and identity name: an
/// observed failure that broke an obligation, or an audit's failing record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Violated {
    Observed(Failure),
    Audit(Record),
}

impl Violated {
    pub(crate) fn code(&self) -> [u8; PAYLOAD] {
        match self {
            Self::Observed(failure) => failure_code(failure),
            Self::Audit(record) => audit_code(record),
        }
    }

    /// `site` applies to an observed failure; an audit is always judged
    /// when the run settles.
    pub(crate) fn identity(&self, site: Site) -> Event {
        match self {
            Self::Observed(failure) => identity_event(failure, site),
            Self::Audit(record) => audit_identity(record),
        }
    }
}

/// The violation code of an audit's failing record: variant 4, then the
/// record's canonical code.
fn audit_code(record: &Record) -> [u8; PAYLOAD] {
    let mut out = [0; PAYLOAD];
    out[0] = 4;
    out[1..8].copy_from_slice(&record_code(record));
    out
}

fn record_code(record: &Record) -> [u8; 7] {
    let [reason, first, second] = reason_code(record.reason);
    let (place, actor, toward) = source_parts(record.source);
    let toward = toward as u8;
    let actor = actor.to_le_bytes();
    [
        record.class as u8,
        reason,
        first,
        second,
        place,
        actor[0],
        toward ^ (actor[1] << 4),
    ]
}

/// An audit source's place code (1 a link, 2 a device), its actor, and
/// the link end it faced, 0 for a device.
fn source_parts(source: Source) -> (u8, u16, usize) {
    match source {
        Source::Link { actor, toward } => (1, actor, toward),
        Source::Device(actor) => (2, actor, 0),
    }
}

/// A capture's canonical code: its tap, link, direction, ordinal, the
/// message kind and fragment index when they decode, and the decision the
/// tap saw.
pub(super) fn capture_code(capture: &Capture) -> [u8; 32] {
    let decision = &capture.decision;
    let (dropped, at) = match decision.drop {
        None => (0, 0),
        Some(Dropped::Fault) => (1, 0),
        Some(Dropped::Rule(at)) => (2, at),
        Some(Dropped::Isolated(at)) => (3, at),
        Some(Dropped::Burst) => (4, 0),
        Some(Dropped::Resend) => (5, 0),
    };
    let flag = |value: Option<bool>| value.map_or(0, |value| 1 + u8::from(value));
    let mut out = [0; 32];
    out[..2].copy_from_slice(&(capture.tap as u16).to_le_bytes());
    out[2..4].copy_from_slice(&capture.link.to_le_bytes());
    out[4] = capture.toward as u8;
    out[5..13].copy_from_slice(&capture.ordinal.to_le_bytes());
    out[13] = capture.kind.map_or(0, |kind| kind as u8);
    out[14..18].copy_from_slice(&capture.index.unwrap_or(u32::MAX).to_le_bytes());
    out[18] = dropped;
    out[19..21].copy_from_slice(&(at as u16).to_le_bytes());
    out[21] = u8::from(decision.duplicate);
    out[22..30].copy_from_slice(&decision.delay.unwrap_or(u64::MAX).to_le_bytes());
    out[30] = flag(decision.reorder) | flag(decision.truncate) << 2;
    out[31] = decision
        .corrupt
        .map_or(0, |corruption| corruption as u8 + 1);
    out
}

/// A failure's canonical code: its variant (1 a violation, 2 an oracle
/// verdict, 3 an unsuccessful check), the obligation it names plus one or
/// zero, then its rule's length and bytes, cut at the payload. A truncated
/// failure is its inner failure's code with bit 7 of the variant set.
pub(super) fn failure_code(failure: &Failure) -> [u8; PAYLOAD] {
    if let Failure::Truncated(inner) = failure {
        let mut code = failure_code(inner);
        code[0] |= TRUNCATED;
        return code;
    }
    let (variant, obligation, rule) = failure_parts(failure);
    let rule = &rule.as_bytes()[..rule.len().min(PAYLOAD - 3)];
    let mut out = [0; PAYLOAD];
    out[0] = variant;
    out[1] = obligation.map_or(0, obligation_code);
    out[2] = rule.len() as u8;
    out[3..3 + rule.len()].copy_from_slice(rule);
    out
}

/// The code a failure's bytes hold for `obligation`: its place among the
/// obligations, counted from 1.
pub(super) fn obligation_code(obligation: Obligation) -> u8 {
    obligation as u8 + 1
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Breach {
    Obligation(Obligation),
    Audit(Class),
}

pub(crate) fn breach(code: &[u8; PAYLOAD]) -> Option<Breach> {
    match code[0] {
        1 | 2 => {
            let obligation = usize::from(code[1]).checked_sub(1)?;
            Obligation::ALL
                .get(obligation)
                .copied()
                .map(Breach::Obligation)
        }
        4 => Class::ALL
            .get(usize::from(code[1]))
            .copied()
            .map(Breach::Audit),
        _ => None,
    }
}

impl Mixed<'_, '_, '_> {
    /// Logs the `PUT` event of the upload action `event`, which returned
    /// `outcome`, after it ran.
    pub(super) fn log_put(&mut self, event: &Candidate, outcome: u64) {
        let (kind, fragment) = put_kind(event);
        let Some(put) = &self.put else {
            return;
        };
        let supplied = match kind {
            ActionKind::Supply => {
                let start = fragment as usize * super::FRAGMENT_LEN as usize;
                let end = (start + super::FRAGMENT_LEN as usize).min(self.object.len());
                content(&self.object[start..end])
            }
            _ => [0; 16],
        };
        let held = match kind {
            ActionKind::DeferSupply => put.deferred_until,
            _ => 0,
        };
        let logged = event_put(
            kind,
            put.attempt,
            put.session.unwrap_or(0),
            fragment,
            &supplied,
            held,
            outcome,
        );
        self.log.push(logged);
    }

    /// Appends what the world produced since the last call.
    pub(super) fn emit_into(&mut self, out: &mut Vec<Event>) {
        self.emitted.puts += self.log.len() as u64;
        out.append(&mut self.log);
        for act in &self.acts[self.emitted.acts..] {
            act_events(out, act.kind, act.outcome, witnessed(act.kind, act.outcome));
        }
        self.emitted.acts = self.acts.len();
        if let Some(put) = &self.put {
            let client = &self.scene.clients[0];
            let (serial, base, grant) = client.put_receipt(put.id).unwrap_or((0, 0, 0));
            let held = client
                .sources()
                .iter()
                .filter(|slot| slot.device_held())
                .count() as u16;
            let outcome = put
                .outcome
                .map_or(0, |outcome| super::upload_code(outcome) as u8 + 1);
            let bound = super::super::adapters::bound(&self.scene, super::PUT_KEY);
            let state = event(
                UPLOAD,
                &[
                    &put.attempt.to_le_bytes(),
                    &serial.to_le_bytes(),
                    &base.to_le_bytes(),
                    &grant.to_le_bytes(),
                    &held.to_le_bytes(),
                    &[outcome, u8::from(bound)],
                ],
            );
            if self.emitted.upload != Some(state.payload) {
                self.emitted.upload = Some(state.payload);
                out.push(state);
            }
        }
        let peer = self.peer.iter().flat_map(|peer| peer.nets());
        for (net, link) in self.scene.nets.iter().chain(peer).enumerate() {
            let link = link.borrow();
            let records = link.audit().records();
            for record in &records[self.emitted.audits[net].min(records.len())..] {
                out.push(audit_event(net as u8, record));
            }
            self.emitted.audits[net] = records.len();
            let captures = link.rules().captures();
            for capture in &captures[self.emitted.captures[net].min(captures.len())..] {
                out.push(event(RULE, &[&[net as u8], &capture_code(capture)]));
            }
            self.emitted.captures[net] = captures.len();
        }
        if !self.emitted.failure
            && let Some(failure) = self.first.get()
        {
            self.emitted.failure = true;
            out.push(failure_event(&failure));
        }
    }
}

/// Pushes onto `out` the `ACT` event of an executed action of `kind` with
/// outcome `outcome`, then its `WITNESS` event when `witnessed`.
pub(super) fn act_events(out: &mut Vec<Event>, kind: ActionKind, outcome: u64, witnessed: bool) {
    let code = outcome.to_le_bytes();
    out.push(event(ACT, &[&[kind as u8], &code]));
    if witnessed {
        out.push(event(WITNESS, &[&[kind as u8], &code]));
    }
}

/// The `AUDIT` event of link `net`'s audit record `record`.
pub(super) fn audit_event(net: u8, record: &Record) -> Event {
    event(AUDIT, &[&[net], &record_code(record)])
}

/// The `FAILURE` event of a failure naming a broken obligation, else the
/// `OBSERVED` event.
pub(super) fn failure_event(failure: &Failure) -> Event {
    Event {
        kind: if violates(failure) { FAILURE } else { OBSERVED },
        payload: failure_code(failure),
    }
}

/// A `PUT` event's fields, as [`event_put`] lays them out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PutRecord {
    /// The upload action, when its code names one.
    pub(super) kind: Option<ActionKind>,
    pub(super) attempt: u16,
    pub(super) session: u64,
    pub(super) fragment: u32,
    /// The first 16 bytes of the SHA-256 of the bytes a supply offered.
    pub(super) supplied: [u8; 16],
    pub(super) held: u64,
    pub(super) outcome: u32,
}

/// The outcome code of an accepted supply: the world's applied code.
pub(super) const SUPPLIED: u32 = super::APPLIED as u32;

impl PutRecord {
    /// The record `event` carries, or `None` for another kind of event.
    pub(super) fn of(event: &Event) -> Option<Self> {
        if event.kind != PUT {
            return None;
        }
        let p = &event.payload;
        Some(Self {
            kind: ActionKind::from_code(p[0]),
            attempt: u16::from_le_bytes([p[1], p[2]]),
            session: u64::from_le_bytes(p[3..11].try_into().expect("eight bytes")),
            fragment: u32::from_le_bytes(p[11..15].try_into().expect("four bytes")),
            supplied: p[15..31].try_into().expect("sixteen bytes"),
            held: u64::from_le_bytes(p[31..39].try_into().expect("eight bytes")),
            outcome: u32::from_le_bytes(p[39..43].try_into().expect("four bytes")),
        })
    }
}

pub(super) fn event_put(
    kind: ActionKind,
    attempt: u16,
    session: u64,
    fragment: u32,
    supplied: &[u8; 16],
    held: u64,
    outcome: u64,
) -> Event {
    event(
        PUT,
        &[
            &[kind as u8],
            &attempt.to_le_bytes(),
            &session.to_le_bytes(),
            &fragment.to_le_bytes(),
            supplied,
            &held.to_le_bytes(),
            &(outcome as u32).to_le_bytes(),
        ],
    )
}

/// What a stream does beside recording its run: it sees every turn and
/// every event the run emits and every stopped boundary, with the recorder
/// holding the records up to that boundary.
pub(super) trait Stops<W: Write> {
    /// Events the world emitted, after the recorder took them.
    fn events(&mut self, _events: &[Event]) {}

    /// A turn applied, after the recorder took it and before its events.
    fn turn(&mut self, _turn: &Turn) {}

    /// A stopped boundary, after its clock move and events are recorded.
    fn stopped(&mut self, _recorder: &mut Recorder<W>, _chooser: &RefCell<Chooser>) {}

    /// A turn's selection among `runnable` is next.
    fn select(
        &mut self,
        _recorder: &mut Recorder<W>,
        _runnable: &[Candidate],
        _chooser: &RefCell<Chooser>,
    ) {
    }
}

/// A stream that only records.
impl<W: Write> Stops<W> for () {}

/// Streams a run into a bundle recorder: a `FAILURE` event becomes the
/// recorder's flushed violation, and makes the run's failure one that
/// surfaced at [`Site::Run`].
struct Streamed<W: Write, S> {
    recorder: Recorder<W>,
    stops: S,
    site: Site,
}

impl<W: Write, S: Stops<W>> Streamed<W, S> {
    /// A stream whose failure surfaces at [`Site::Settled`] until a
    /// `FAILURE` event arrives.
    fn new(recorder: Recorder<W>, stops: S) -> Self {
        Self {
            recorder,
            stops,
            site: Site::Settled,
        }
    }

    fn events(&mut self, events: &[Event]) {
        for event in events {
            if event.kind == FAILURE {
                self.site = Site::Run;
                self.recorder.violation(&event.payload);
            } else {
                self.recorder.event(event);
            }
        }
        self.stops.events(events);
    }
}

impl<W: Write, S: Stops<W>> Hook for Streamed<W, S> {
    fn begin(&mut self, record: &[u8], choices: &[u8]) {
        self.recorder.field(Field::Config, record);
        self.recorder.choices(choices);
    }

    fn enter(&mut self) {
        self.recorder.enter();
    }

    fn leave(&mut self) {
        self.recorder.leave();
    }

    fn clock(&mut self, choices: &[u8], now: u64, events: &[Event]) {
        self.recorder.choices(choices);
        self.recorder.clock(now);
        self.events(events);
    }

    fn turn(&mut self, choices: &[u8], turn: &Turn, events: &[Event]) {
        self.recorder.choices(choices);
        self.recorder
            .turn(turn.now, &turn.event.0, turn.outcome, &turn.observation);
        self.stops.turn(turn);
        self.events(events);
    }

    fn stopped(&mut self, chooser: &RefCell<Chooser>) {
        self.stops.stopped(&mut self.recorder, chooser);
    }

    fn select(&mut self, runnable: &[Candidate], chooser: &RefCell<Chooser>) {
        self.stops.select(&mut self.recorder, runnable, chooser);
    }

    fn end(&mut self, choices: &[u8]) {
        self.recorder.choices(choices);
    }
}

/// Why the worker refused a manifest before its run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// No profile goes by the manifest's name.
    Profile,
    /// A manifest bound is below what the run can hold.
    Bound(&'static str),
    /// The scenario encoding does not parse or does not reduce the profile's.
    Scenario,
    /// The canonical manifest needs more chunks than one field records.
    Field,
}

/// A run's profile, plan and goal.
pub(super) type Scenario = (
    crate::sim::action::Profile,
    Plan,
    fn(&Mixed<'_, '_, '_>) -> bool,
);

/// A string only the simulated worlds hold, compiled under `cfg(test)` with
/// them. A control run looks up its scenario through [`named`], which
/// passes the mark to `black_box`, so a binary that links [`named`] holds
/// its bytes. The literal is spelled in two pieces, so a copy of this file
/// that a test embeds keeps the pieces apart. An integration test scans the
/// crate's non-test binaries for the whole mark.
const CONTROL_MARK: &str = concat!("kestrike control ", "profile mark");

/// `profile` also declaring a deferral, for planted scenarios a reducer
/// strips.
fn noisy(mut profile: crate::sim::action::Profile) -> crate::sim::action::Profile {
    profile.declared.push(ActionKind::DeferSupply);
    profile
}

/// Each control that runs another profile's scenario over a resident
/// record whose payload byte changed before the run, with that profile.
/// The first stopped boundary of the run fails the Bytes obligation.
pub(super) const CORRUPTED: [(&str, &str); 13] = [
    ("faulted-corrupted", "faulted"),
    ("local-corrupted", "local"),
    ("control-corrupted", "control"),
    ("deferring-corrupted", "deferring"),
    ("uncertain-corrupted", "uncertain"),
    ("failing-corrupted", "failing"),
    ("replacing-corrupted", "replacing"),
    ("settled-corrupted", "settled"),
    ("boundary-tiny-corrupted", "boundary-tiny"),
    ("boundary-collision-corrupted", "boundary-collision"),
    ("boundary-fragmentation-corrupted", "boundary-fragmentation"),
    ("boundary-mixed-size-corrupted", "boundary-mixed-size"),
    ("boundary-real-counter-corrupted", "boundary-real-counter"),
];

/// Whether the world observed a failure or the owner refused the stranger
/// key's GET as `Missing` with every declared kind reached.
fn failed_or_refused(world: &Mixed<'_, '_, '_>) -> bool {
    world.first.get().is_some() || super::refused_read(world)
}

/// Whether the world observed a failure or every declared kind ran with
/// its witness.
fn failed_or_covered(world: &Mixed<'_, '_, '_>) -> bool {
    world.first.get().is_some() || world.covered()
}

/// Whether the world observed a failure or read its upload back.
fn failed_or_read(world: &Mixed<'_, '_, '_>) -> bool {
    world.first.get().is_some() || published_then_read(world)
}

const UPLOAD_PUBLISHED: &str = "the upload published";

/// A plan that reads after publication issues no GET once its last upload
/// ended unpublished, so the run finishes there once the world drained.
fn read_or_unpublished(world: &Mixed<'_, '_, '_>) -> bool {
    exactly_read(world) || world.unpublished() && super::relation::undrained(world).is_none()
}

/// The profile, plan and goal the manifest's profile name selects: the
/// upload profile until its upload is read back, the same over a resident
/// record whose payload byte changed before the run, the same over links
/// that lose, duplicate, reorder and delay traffic under a tapped rule
/// until the read returns exact bytes, a planted scenario until its failure
/// shows or its upload is read back, or a coverage profile until each
/// declared kind ran with its witness. The planted scenarios run a deferring
/// upload over faulty links with two reads, and either change the
/// published record's payload or, with every upload result dropped, claim
/// publication on acknowledgment; `panicking` runs the first planted
/// scenario's plan with a world that panics once the upload publishes, and
/// `asserting` runs it with a world whose debug assertion fails then. A
/// `boundary-` name selects a scenario that walks up to one resource
/// boundary, and `long` and `long-planted` the long mixed run, as
/// [`boundary`](super::boundary) defines them. A `recovery-16k`,
/// `recovery-512` or `recovery-torn` name selects the upload scenario under
/// that [`Recovery`] profile, whose record the run's Config carries. A
/// name of [`CORRUPTED`] selects its profile's scenario over a resident
/// record whose payload byte changed before the run. `misread` runs the
/// upload scenario with a world that changes the first byte a complete
/// read hands its client, `staged-hit` the upload scenario with two
/// reads issued before the upload publishes and a world that hands a
/// read the owner refused as `Missing`, while its index never bound the
/// upload's key, the upload's object as a complete read, `failing-hit`
/// the `failing` scenario with a world that hands the stranger key's GET
/// the resident object as a complete read, `failing-exposed` that
/// scenario with a world that hands the refused GET one byte,
/// `uncertain-published` the `uncertain` scenario with a world that
/// collects an unknown upload outcome as published, `leaked` the upload
/// scenario with a world that leaks one payload unit once the publication
/// is collected, and `uncounted` the upload scenario with a multiplexer
/// that drops one lease it received and reports one fewer; each runs until
/// its
/// failure shows or its scenario's goal holds. `contended` runs the
/// `faulted` plan with the storage's chaos points armed, until the read
/// returns the uploaded bytes or the upload ends unpublished and the world
/// drains. `contended-acked` runs that plan with a world that records an
/// upload as published when the owner refuses it with `Contended`, until a
/// failure appears or the upload is read back.
///
/// The episode scenarios read the resident object once from each client
/// after a held update, `rekey` after one rekey and `replacing` after one
/// session change, until each read decides and every episode settles as
/// [`Episode::healed`](super::Episode::healed) requires. `rekey-stalled` is
/// `rekey` with the GET client's episode left unread. `failing` reads the
/// stranger key until the owner refuses it as `Missing`.
pub(super) fn named(name: &str, root: u64) -> Option<Scenario> {
    std::hint::black_box(CONTROL_MARK);
    if !super::catalog::listed(name) {
        return None;
    }
    if let Some(cluster) = super::cluster::named(name, root) {
        return Some(cluster);
    }
    if let Some(history) = super::histories::named(name, root) {
        return Some(history);
    }
    if let Some(base) = CORRUPTED
        .iter()
        .find_map(|(control, base)| (*control == name).then_some(*base))
    {
        let (profile, plan, goal) = named(base, root)?;
        let plan = Plan {
            corrupt_resident: true,
            ..plan
        };
        return Some((profile, plan, goal));
    }
    let [local, control, deferring, uncertain] = coverage(root);
    let covered: fn(&Mixed<'_, '_, '_>) -> bool = |world| world.covered();
    let (profile, plan) = match name {
        "upload" => return Some((upload_profile(root), UPLOAD_PLAN, published_then_read)),
        name if recovery_profile(name) => {
            let plan = Plan {
                world: WorldKind::Recovery(Recovery::named(name)?),
                ..UPLOAD_PLAN
            };
            return Some((upload_profile(root), plan, published_then_read));
        }
        "corrupted" => {
            let plan = Plan {
                corrupt_resident: true,
                ..UPLOAD_PLAN
            };
            return Some((upload_profile(root), plan, published_then_read));
        }
        "planted" => {
            let profile = noisy(upload_profile(root));
            let plan = Plan {
                gets: [0, 2],
                withhold: 1,
                link_faults: true,
                plant: Plant::PublishedByte,
                ..UPLOAD_PLAN
            };
            return Some((profile, plan, failed_or_read));
        }
        "panicking" | "asserting" => {
            let profile = noisy(upload_profile(root));
            let plan = Plan {
                gets: [0, 2],
                withhold: 1,
                link_faults: true,
                plant: if name == "panicking" {
                    Plant::Panic
                } else {
                    Plant::DebugAssertion
                },
                ..UPLOAD_PLAN
            };
            return Some((profile, plan, failed_or_read));
        }
        "acked" => {
            let profile = noisy(upload_profile(root));
            let plan = Plan {
                gets: [0, 2],
                withhold: 1,
                link_faults: true,
                read_after_publish: false,
                drop_result: true,
                plant: Plant::AckAsSuccess,
                ..UPLOAD_PLAN
            };
            return Some((profile, plan, failed_or_read));
        }
        "misread" => {
            let plan = Plan {
                plant: Plant::ChangedRead,
                ..UPLOAD_PLAN
            };
            return Some((upload_profile(root), plan, failed_or_read));
        }
        "staged-hit" => {
            let plan = Plan {
                gets: [0, 2],
                read_after_publish: false,
                plant: Plant::StagedHit,
                ..UPLOAD_PLAN
            };
            return Some((upload_profile(root), plan, failed_or_read));
        }
        "leaked" => {
            let plan = Plan {
                plant: Plant::LeakedUnit,
                ..UPLOAD_PLAN
            };
            return Some((upload_profile(root), plan, failed_or_read));
        }
        "uncounted" => {
            let plan = Plan {
                plant: Plant::Uncounted,
                ..UPLOAD_PLAN
            };
            return Some((upload_profile(root), plan, failed_or_read));
        }
        "failing-hit" | "failing-exposed" => {
            let (profile, plan, _) = named("failing", root)?;
            let plan = Plan {
                plant: if name == "failing-hit" {
                    Plant::UnpublishedHit
                } else {
                    Plant::ExposedMiss
                },
                ..plan
            };
            return Some((profile, plan, failed_or_refused));
        }
        "uncertain-published" => {
            let (profile, plan, _) = named("uncertain", root)?;
            let plan = Plan {
                plant: Plant::UnknownAsSuccess,
                ..plan
            };
            return Some((profile, plan, failed_or_covered));
        }
        "faulted" => {
            let plan = Plan {
                link_faults: true,
                ..UPLOAD_PLAN
            };
            return Some((upload_profile(root), plan, exactly_read));
        }
        "contended" => {
            let (profile, plan, _) = named("faulted", root)?;
            let plan = Plan {
                chaos: true,
                ..plan
            };
            return Some((profile, plan, read_or_unpublished));
        }
        "contended-acked" => {
            let (profile, plan, _) = named("contended", root)?;
            let plan = Plan {
                plant: Plant::ContendedAsSuccess,
                ..plan
            };
            return Some((profile, plan, failed_or_read));
        }
        name if name.starts_with("settled") => return settled(name, root),
        name if name.starts_with("boundary-") => return super::boundary::named(name, root),
        "long" | "long-planted" => {
            return Some(super::boundary::long(name == "long-planted", root));
        }
        "rekey" | "rekey-stalled" | "replacing" => {
            let rekey = name != "replacing";
            let held = if rekey {
                ActionKind::Rekey
            } else {
                ActionKind::SessionChange
            };
            let profile = Profile {
                name: if rekey {
                    "a rekey, then a read from each client"
                } else {
                    "a session change, then a read from each client"
                },
                declared: vec![ActionKind::Get, ActionKind::Read, held],
                root,
            };
            let plan = Plan {
                gets: [1, 1],
                read_resident: true,
                rekeys: u32::from(rekey),
                sessions: u32::from(!rekey),
                episodes: true,
                plant: if name == "rekey-stalled" {
                    Plant::StalledHeal
                } else {
                    Plant::None
                },
                ..QUIET
            };
            return Some((profile, plan, healed));
        }
        "failing" => {
            let profile = Profile {
                name: "a read of a key never published",
                declared: vec![ActionKind::Get, ActionKind::Read],
                root,
            };
            let plan = Plan {
                gets: [0, 1],
                read_stranger: true,
                ..QUIET
            };
            return Some((profile, plan, refused_read));
        }
        "local" => local,
        "control" => control,
        "deferring" => deferring,
        "uncertain" => uncertain,
        _ => return None,
    };
    Some((profile, plan, covered))
}

/// A settled scenario: the upload profile until its upload is read back
/// exactly, then [`DRAIN`](super::relation::DRAIN) drain turns; under
/// `hasty` the goal holds while a COMPLETE frame heads link 1's queue. The
/// `-`-separated words after `settled` apply left to right, each to the
/// inputs the earlier words left: the geometry words replace one another,
/// `twice` and `invalidating` double the drain in place and `hasty` empties
/// it. `batched` sets the owner's batch to three, `scaled` the geometry to
/// a larger one and `cramped` to one too small for the work, `eager` issues
/// a read before the upload publishes, `faulted` faults the links,
/// `planted` changes a published byte once the goal holds, and
/// `invalidating` also declares the invalidate action and proposes one
/// invalidation once the goal holds.
fn settled(name: &str, root: u64) -> Option<Scenario> {
    let mut profile = upload_profile(root);
    let mut plan = Plan {
        drain: super::relation::DRAIN,
        ..UPLOAD_PLAN
    };
    let mut words = name.split('-');
    if words.next() != Some("settled") {
        return None;
    }
    for word in words {
        match word {
            "batched" => plan.batch = Some(3),
            "scaled" => plan.geometry = super::Geometry::Scaled,
            "cramped" => plan.geometry = super::Geometry::Cramped,
            "twice" => plan.drain = plan.drain.checked_mul(2)?,
            "hasty" => plan.drain = 0,
            "eager" => plan.read_after_publish = false,
            "faulted" => plan.link_faults = true,
            "planted" => plan.plant = Plant::SettledByte,
            "invalidating" => {
                profile.declared.push(ActionKind::Invalidate);
                plan.invalidations = 1;
                // The suffix's GETs of the invalidated key end on misses, and the doubled drain lets their requests leave the owner.
                plan.drain = plan.drain.checked_mul(2)?;
            }
            _ => return None,
        }
    }
    let goal: fn(&Mixed<'_, '_, '_>) -> bool = if plan.drain == 0 {
        |world| {
            world.scene.nets[1].borrow().peek(0).is_some_and(|bytes| {
                parse(crate::storage::Crc32c::detect(), &bytes, false)
                    .is_ok_and(|frame| frame.header().kind == Kind::Complete)
            })
        }
    } else {
        super::exactly_read
    };
    Some((profile, plan, goal))
}

/// Obligations a mixed or cluster run checks at every stopped boundary: the
/// registry against bindings and raw media.
const CHECKED: [Obligation; 2] = [Obligation::Bytes, Obligation::History];

/// A mixed or cluster run's terminal and the violation its bundle records,
/// from how the controller ended, the first failure a boundary or teardown
/// observed, the link and device audit, whether the profile declares
/// uploads and how many upload actions a mixed run emitted or uploads a
/// cluster run started, and how many stopped boundaries ran. Each outcome
/// comes with its violation:
///
/// - a run a hook halted is a sink failure, ahead of every other rule, since
///   its stream stopped before the run ended;
/// - a defect is infrastructure, keeping a violating observation or audit
///   record as evidence;
/// - an observed violation, else an audit's failing record, is a violation
///   naming it;
/// - otherwise an unsuccessful or truncated observation is unsuccessful,
///   and an inconclusive oracle verdict, an inconclusive audit or a limit is
///   inconclusive;
/// - a finished run that declares uploads and recorded none is
///   unsuccessful, and any other finished run passes.
///
/// The boundary obligations fire once a boundary ran. The returned
/// [`Violated`] yields both the violation record and its [`IDENTITY`]
/// event.
pub(crate) fn judge(
    end: End,
    failure: Option<&Failure>,
    audit: Verdict,
    (declares_put, puts): (bool, u64),
    boundaries: usize,
) -> (Terminal, Option<Violated>) {
    let required = CHECKED
        .iter()
        .fold(0, |mask, &obligation| mask | bit(obligation));
    let fired = if boundaries > 0 { required } else { 0 };
    let complete = |outcome| Terminal::Complete {
        outcome,
        fired,
        required,
    };
    let violation = match (failure, audit) {
        (Some(failure), _) if violates(failure) => Some(Violated::Observed(failure.clone())),
        (_, Verdict::Fail(record)) => Some(Violated::Audit(record)),
        _ => None,
    };
    let terminal = match (end, failure, audit) {
        (End::Defect(_), _, _) => Terminal::Infrastructure(Infrastructure::Defect),
        (End::Halted, _, _) => Terminal::Infrastructure(Infrastructure::Sink),
        _ if violation.is_some() => complete(Outcome::Violation),
        (_, Some(Failure::Unsuccessful(_) | Failure::Truncated(_)), _) => {
            complete(Outcome::Unsuccessful)
        }
        // The failure left here is an oracle verdict that is no violation.
        (_, Some(_), _) | (_, None, Verdict::Inconclusive(_)) | (End::Inconclusive(_), None, _) => {
            complete(Outcome::Inconclusive)
        }
        (End::Done, None, _) if declares_put && puts == 0 => complete(Outcome::Unsuccessful),
        (End::Done, None, _) => complete(Outcome::Pass),
    };
    (terminal, violation)
}

/// A manifest admitted for its run, with the scenario it names.
pub(crate) struct Admitted<'m> {
    manifest: &'m Manifest,
    scenario: Scenario,
}

/// Why a recovery bundle's record refuses its replay before the first
/// turn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unadmitted {
    /// A recovery profile's Config field holds no record that parses, or a
    /// live profile's embeds one.
    Record(RecordError),
    /// The record differs from the one this executable derives for the
    /// bundle's profile.
    Mismatch(Mismatch),
}

impl Admitted<'_> {
    /// The link limits the admitted manifest declares.
    pub(crate) fn link(&self) -> LinkLimits {
        let bound = |key| usize::try_from(self.manifest.count(key)).unwrap_or(usize::MAX);
        LinkLimits {
            copy_bytes: bound("link_copy_bytes"),
            tx_slots: bound("tx_slots"),
        }
    }

    /// The turn limits the admitted manifest declares.
    pub(crate) fn limits(&self) -> Limits {
        Limits {
            total: self.manifest.count("turns"),
            same_time: self.manifest.count("same_time"),
            no_progress: self.manifest.count("no_progress"),
        }
    }

    /// The content registry bound the admitted manifest declares.
    pub(crate) fn registry(&self) -> usize {
        usize::try_from(self.manifest.count("registry")).unwrap_or(usize::MAX)
    }

    /// The cluster profile the admitted manifest names, if it names one.
    pub(crate) fn cluster(&self) -> Option<&'static super::cluster::Shape> {
        match self.scenario.1.world {
            WorldKind::Cluster(shape) => Some(shape),
            WorldKind::Mixed | WorldKind::Recovery(_) => None,
        }
    }

    /// The admitted manifest and the scenario's profile.
    pub(crate) fn parts(&self) -> (&Manifest, &crate::sim::action::Profile) {
        (self.manifest, &self.scenario.0)
    }

    /// A chooser recording the scenario's decisions from its root, under
    /// the recovery profile's admission when the scenario has one.
    pub(crate) fn recorder(&self) -> Chooser {
        self.admit(self.scenario.0.recorder(&sites_of(&self.scenario)))
    }

    /// A chooser replaying `loaded`'s tape, under the recovery profile's
    /// admission when the scenario has one.
    ///
    /// # Errors
    ///
    /// Before any decision: the recorded record's parse error, `Live` for a
    /// live profile's Config embedding a record, or under a recovery
    /// profile the record's first field differing from the one this
    /// executable derives.
    pub(crate) fn replayer(&self, loaded: &Loaded) -> Result<Chooser, Unadmitted> {
        let record = admitted(&loaded.fields).map_err(Unadmitted::Record)?;
        if let Some(recovery) = self.scenario.1.recovery() {
            record
                .ok_or(Unadmitted::Record(RecordError::Absent))?
                .check(&recovery.record())
                .map_err(Unadmitted::Mismatch)?;
        }
        Ok(self.admit(Chooser::replay(
            &sites_of(&self.scenario),
            loaded.tape.clone(),
        )))
    }

    /// A chooser reading every decision from `feed`, under the recovery
    /// profile's admission when the scenario has one.
    pub(crate) fn fed(&self, feed: Vec<u8>) -> Chooser {
        self.admit(Chooser::fed(&sites_of(&self.scenario), feed))
    }

    /// Whether the scenario runs the mixed world, the one world that draws
    /// the mixed setup entropy.
    pub(crate) fn live(&self) -> bool {
        matches!(self.scenario.1.world, WorldKind::Mixed)
    }

    /// Whether the scenario runs the mixed world on links that return a
    /// transmit's device references at delivery, in the owner's receive.
    pub(crate) fn at_delivery(&self) -> bool {
        self.live() && self.scenario.1.tx_release() == super::super::link::TxRelease::AtDelivery
    }

    fn admit(&self, chooser: Chooser) -> Chooser {
        match self.scenario.1.recovery() {
            Some(recovery) => chooser.admitting(recovery.admission()),
            None => chooser,
        }
    }
}

/// Checks the manifest against the run it names before anything records:
/// each resource row the run holds at a fixed size must declare at least
/// that size. `traced` applies the link bounds, turn limits and recorder
/// capacities, and the launcher the watchdog; `restarts` and `bundles`
/// bound relaunches, and a mixed history holds them against the
/// relaunches its script runs and the one dead bundle a relaunch holds
/// from the owner's death until its release, before the next incarnation
/// starts.
///
/// # Errors
///
/// A [`Refusal`] when the manifest names no profile, a bound below the
/// run's, or a canonical text one field cannot record.
pub(crate) fn admit(manifest: &Manifest) -> Result<Admitted<'_>, Refusal> {
    let scenario = scenario(manifest)?;
    let bounds = held(&scenario);
    let canonical = manifest.canonical().len();
    let admitted = Admitted { manifest, scenario };
    match bounds
        .iter()
        .find(|(key, least)| manifest.count(key) < *least)
    {
        Some((key, _)) => Err(Refusal::Bound(key)),
        None if canonical.div_ceil(crate::sim::trace::CHUNK) as u64
            > crate::sim::trace::FIELD_CHUNKS =>
        {
            Err(Refusal::Field)
        }
        None if !manifest.capacity().holds_field(canonical) => Err(Refusal::Bound("records")),
        None => Ok(admitted),
    }
}

/// The manifest counts admission holds against a scenario's own bounds.
pub(crate) const HELD: [&str; 13] = [
    "actors",
    "disk_depth",
    "scripted",
    "rules",
    "taps",
    "captures",
    "audit_records",
    "registry",
    "upload_attempts",
    "source_bytes",
    "slots",
    "restarts",
    "bundles",
];

/// The least value of each [`HELD`] count, in its order, the manifest of
/// the scenario `name` names must hold; `None` for a name no profile goes
/// by. The capability listing prints these.
pub(crate) fn held_by(name: &str) -> Option<[(&'static str, u64); HELD.len()]> {
    named(name, 1).map(|scenario| held(&scenario))
}

pub(crate) fn composed_by(name: &str) -> Option<(u16, u16)> {
    named(name, 1)
        .filter(|scenario| matches!(scenario.1.world, WorldKind::Mixed))
        .map(|scenario| composition(&scenario.1))
}

/// The sites `scenario`'s world decides at: the recovery world's under a
/// recovery profile, the cluster world's under a cluster profile, the
/// mixed world's otherwise.
fn sites_of(scenario: &Scenario) -> Vec<crate::sim::choice::Site> {
    match scenario.1.world {
        WorldKind::Recovery(_) => super::recovery::sites().to_vec(),
        WorldKind::Cluster(_) => super::cluster::sites(),
        WorldKind::Mixed => super::sites_for(&scenario.1),
    }
}

/// The least value of each [`HELD`] count `scenario`'s run needs.
fn held(scenario: &Scenario) -> [(&'static str, u64); HELD.len()] {
    let plan = scenario.1;
    let actors: std::collections::BTreeSet<u16> =
        sites_of(scenario).iter().map(|site| site.actor).collect();
    let scripted = [
        plan.unattributed,
        plan.corrupt_resident,
        plan.short_link,
        plan.lose_upload,
    ];
    let (attempts, source) = match plan.world {
        WorldKind::Cluster(shape) => (shape.upload_attempts(), shape.source_bytes()),
        WorldKind::Mixed | WorldKind::Recovery(_) => (
            u64::from(plan.puts + plan.retries),
            u64::from(plan.source_bytes),
        ),
    };
    [
        ("actors", actors.len() as u64),
        (
            "disk_depth",
            u64::from(crate::storage::owner_fixture::DEPTH),
        ),
        (
            "scripted",
            (scripted.into_iter().filter(|&on| on).count() + plan.script.len()) as u64,
        ),
        ("rules", MANIFEST.rules as u64),
        ("taps", MANIFEST.taps as u64),
        ("captures", MANIFEST.captures as u64),
        ("audit_records", MANIFEST.records as u64),
        ("registry", MANIFEST.captures as u64),
        ("upload_attempts", attempts),
        ("source_bytes", source),
        ("slots", 1),
        ("restarts", u64::from(plan.relaunches)),
        ("bundles", u64::from(plan.relaunches > 0)),
    ]
}

/// The scenario `manifest` names: its profile's, or the reduction of it the
/// manifest's scenario encodes.
///
/// # Errors
///
/// `Profile` for an unknown profile name, `Scenario` for an encoding that
/// does not parse or does not reduce the profile's scenario.
pub(super) fn scenario(manifest: &Manifest) -> Result<Scenario, Refusal> {
    let base = named(&manifest.profile, manifest.root).ok_or(Refusal::Profile)?;
    if manifest.scenario == "base" {
        return Ok(base);
    }
    // Cluster runs derive their operations from their shape, so only the
    // base scenario is admissible.
    if matches!(base.1.world, WorldKind::Cluster(_)) {
        return Err(Refusal::Scenario);
    }
    let edit = super::replay::Edit::decode(&manifest.scenario).ok_or(Refusal::Scenario)?;
    let (profile, plan) = edit.apply(&base.0, base.1).ok_or(Refusal::Scenario)?;
    Ok((profile, plan, base.2))
}

/// Runs the admitted manifest's profile into a bundle over `sink` under
/// the manifest's recorder capacities, and closes it. The first failure a
/// stopped boundary or teardown observed, when it names a broken
/// obligation, else the audit's failing record, is the bundle's violation,
/// as [`judge`] pairs them.
pub(crate) fn traced<W: Write>(admitted: Admitted<'_>, sink: W) -> Closed<W> {
    let chooser = admitted.recorder();
    run_into(admitted, sink, chooser).0
}

/// [`traced`] with every decision from `chooser`, a recording or a
/// replaying one; also returns how the controller ended and the chooser's
/// finish, which refuses a replayed tape with input left.
pub(crate) fn run_into<W: Write>(
    admitted: Admitted<'_>,
    sink: W,
    chooser: Chooser,
) -> (Closed<W>, End, Result<Vec<u8>, ChoiceError>) {
    let (closed, end, finished, ()) = run_stopping(admitted, sink, chooser, ());
    (closed, end, finished)
}

/// [`run_into`] with `stops` seeing the run's events and stopped
/// boundaries as it records them; also returns `stops`.
pub(super) fn run_stopping<W: Write, S: Stops<W>>(
    admitted: Admitted<'_>,
    sink: W,
    chooser: Chooser,
    stops: S,
) -> (Closed<W>, End, Result<Vec<u8>, ChoiceError>, S) {
    let (closed, end, finished, stops, _) = run_settled(admitted, sink, chooser, stops);
    (closed, end, finished, stops)
}

/// What [`run_settled`] returns: the closed recorder, how the controller
/// ended, the chooser's finish, the stream, and what a mixed run settled
/// to; a recovery or cluster run settles to nothing.
pub(super) type Settled<W, S> = (
    Closed<W>,
    End,
    Result<Vec<u8>, ChoiceError>,
    S,
    Option<super::relation::Settled>,
);

/// [`run_stopping`] that also returns what the run settled to.
pub(super) fn run_settled<W: Write, S: Stops<W>>(
    admitted: Admitted<'_>,
    sink: W,
    chooser: Chooser,
    stops: S,
) -> Settled<W, S> {
    let (limits, registry, link) = (admitted.limits(), admitted.registry(), admitted.link());
    let Admitted {
        manifest,
        scenario: (profile, plan, goal),
    } = admitted;
    let mut recorder = Recorder::new(sink, manifest.capacity());
    let bound = |key| usize::try_from(manifest.count(key)).unwrap_or(usize::MAX);
    let plan = Plan { link, ..plan };
    recorder.field(Field::Manifest, manifest.canonical().as_bytes());
    recorder.diagnostic(&format!("cpu {}", manifest.cpu));
    let mut streamed = Streamed::new(recorder, stops);
    let (mut coverage, mut settled) = (None, None);
    let (report, draws, (terminal, violation), mixed, composed) = match plan.world {
        WorldKind::Cluster(shape) => {
            let ran = super::cluster::run(
                chooser,
                &profile,
                shape,
                (limits, registry, plan.link),
                &mut streamed,
            );
            let judged = judge(
                ran.report.end,
                ran.failure.as_ref(),
                ran.audit,
                (profile.declares(ActionKind::PutInvoke), ran.puts),
                ran.boundaries as usize,
            );
            let composed = ran.topology.map(|topology| Composed {
                checked: ran.boundaries,
                owners: u16::from(topology.owners),
                clients: super::cluster::CLIENTS as u16,
            });
            settled = ran
                .failure
                .as_ref()
                .filter(|failure| !ran.failure_emitted && !violates(failure))
                .map(failure_event);
            coverage = ran
                .topology
                .map(|topology| super::cluster::coverage_event(topology, &ran.reached));
            (ran.report, ran.draws, judged, None, composed)
        }
        WorldKind::Recovery(recovery) => {
            let bounds = super::recovery::Bounds {
                lifecycle: super::super::restart::Manifest {
                    slots: bound("slots"),
                    restarts: bound("restarts"),
                    bundles: bound("bundles"),
                },
                link: plan.link,
                turns: limits,
            };
            let ran = super::recovery::run(chooser, &profile, recovery, bounds, &mut streamed);
            let judged = judge_recovery(&ran);
            (ran.report, ran.draws, judged, None, None)
        }
        WorldKind::Mixed => {
            let declares_put = profile.declares(ActionKind::PutInvoke);
            let (ran, failure, puts) =
                mixed_run(chooser, &profile, plan, goal, limits, &mut streamed);
            // A control's run that recorded no failure names whether its
            // plant took effect, so it is no pass.
            let unmet = (plan.control() && failure.is_none())
                .then(|| super::cluster::unmet(ran.report.end, ran.acted))
                .flatten();
            // A completed non-control chaos run requires positive evidence
            // of publication, even when `ran.put` is `None`.
            let published = matches!(
                ran.put,
                Some((Some(super::super::upload::UploadOutcome::Published), _))
            );
            let unpublished = plan.chaos
                && !plan.control()
                && failure.is_none()
                && ran.report.end == End::Done
                && !published;
            let unmet = unmet.or(unpublished.then_some(Failure::Unsuccessful(UPLOAD_PUBLISHED)));
            settled = unmet.as_ref().map(failure_event);
            let failure = failure.or(unmet);
            let judged = judge(
                ran.report.end,
                failure.as_ref(),
                ran.audit,
                (declares_put, puts),
                ran.boundaries,
            );
            let (owners, clients) = composition(&plan);
            let composed = Composed {
                checked: ran.boundaries as u64,
                owners,
                clients,
            };
            (
                ran.report,
                ran.draws,
                judged,
                Some(ran.settled),
                Some(composed),
            )
        }
    };
    let decisions = draws.borrow().decisions();
    let Streamed {
        mut recorder,
        stops,
        site,
    } = streamed;
    if let End::Defect(Defect::Entropy(refusal)) = report.end {
        recorder.event(&entropy_event(refusal));
    }
    // A failure that surfaced during the run already holds its violation
    // record; one judged at settlement takes it here. The identity follows
    // the violation record and precedes the stop event, so a recorder that
    // reaches its cap in this block drops the stop event and closes as
    // capped, which ends the bundle as an infrastructure cap.
    if let Some(violated) = violation {
        record_violation(&mut recorder, &violated, site);
    }
    if let Some(coverage) = coverage {
        recorder.event(&coverage);
    }
    // A cluster failure recorded once the controller returned, by the
    // teardown check or the minimum check, takes its `OBSERVED` event here.
    if let Some(observed) = settled {
        recorder.event(&observed);
    }
    recorder.event(&stop_event(report.end, composed));
    recorder.diagnostic(&format!("wall {:?}", report.wall));
    let work = Work {
        turns: report.turn_count,
        decisions,
        progress: report.progress,
        virtual_us: report.virtual_us,
        skipped_us: report.skipped_us,
    };
    let end = report.end;
    let finished = std::rc::Rc::try_unwrap(draws)
        .expect("the scene released the chooser")
        .into_inner()
        .finish();
    (recorder.finish(terminal, work), end, finished, stops, mixed)
}

/// Records a violation judged at settlement: its violation record, then
/// its identity at `site`.
fn record_violation<W: Write>(recorder: &mut Recorder<W>, violated: &Violated, site: Site) {
    recorder.violation(&violated.code());
    recorder.event(&violated.identity(site));
}

/// A recovery run's terminal and violation: a failed check is the
/// violation record, a Restart violation naming the oracle's rule or the
/// conservation rule's text, kept under every terminal. A run a hook
/// halted is a sink failure ahead of every other rule. A defect is
/// infrastructure; a failed check is a complete violation ahead of a
/// lifecycle step that refused or an unreadable conservation snapshot,
/// which is unsuccessful; a limit, a check without a verdict, or a cut skipped at
/// the restart bound, is inconclusive; any other finished run passes. The
/// Restart obligation is required, and fires once a check passes it. The
/// failed check surfaces when the run settles.
pub(super) fn judge_recovery(ran: &super::recovery::Ran) -> (Terminal, Option<Violated>) {
    let required = bit(Obligation::Restart);
    let fired = if ran.restarted { required } else { 0 };
    let complete = |outcome| Terminal::Complete {
        outcome,
        fired,
        required,
    };
    let violation = ran
        .failed
        .map(|rule| Violated::Observed(Failure::Violation(Obligation::Restart, rule)));
    let terminal = match (ran.report.end, ran.broken, ran.failed, ran.inconclusive) {
        (End::Defect(_), ..) => Terminal::Infrastructure(Infrastructure::Defect),
        (End::Halted, ..) => Terminal::Infrastructure(Infrastructure::Sink),
        (_, _, Some(_), _) => complete(Outcome::Violation),
        (_, Some(_), None, _) => complete(Outcome::Unsuccessful),
        (End::Inconclusive(_), None, None, _) | (_, None, None, Some(_)) => {
            complete(Outcome::Inconclusive)
        }
        (End::Done, None, None, None) if ran.skipped => complete(Outcome::Inconclusive),
        (End::Done, None, None, None) => complete(Outcome::Pass),
    };
    (terminal, violation)
}

/// Changes a payload byte of the record the owner binds under key `name`
/// on the device, once it binds one; returns whether it did.
pub(super) fn change_published(scene: &super::Scene<'_, '_>, name: u8) -> bool {
    let Some(range) = bound_media(scene, name) else {
        return false;
    };
    flip_payload(&scene.control, range);
    true
}

/// The device byte range of the record the owner binds under key `name`.
pub(super) fn bound_media(
    scene: &super::Scene<'_, '_>,
    name: u8,
) -> Option<std::ops::Range<usize>> {
    let (mut bindings, mut facts, mut buffer) = (Vec::new(), Vec::new(), Vec::new());
    let media = scene.media();
    let storage = media.storage();
    if storage.bindings_into(&mut bindings).is_err() || storage.slot_facts_into(&mut facts).is_err()
    {
        return None;
    }
    let wanted = super::key(name);
    let found = bindings.iter().find(|&&binding| {
        media
            .bound_record(binding, &facts, &mut buffer)
            .is_ok_and(|(key, _, _)| key == wanted)
    });
    found.and_then(|binding| facts[binding.identity.slot as usize].media())
}

/// Changes one payload byte of the record whose media is `range`: the byte
/// 300 bytes in, past its header.
pub(super) fn flip_payload(
    control: &crate::storage::owner_fixture::SimControl,
    range: std::ops::Range<usize>,
) {
    let at = range.start + 300;
    let byte = control.device(at, 1)[0];
    control.write_device(at, &[byte ^ 0x5a]);
}

/// An upload's fragment count in the mixed world: three, the last short.
pub(super) const FRAGMENTS: u32 = super::OBJECT_LEN.div_ceil(super::FRAGMENT_LEN);

/// An `UPLOAD` event's fields, as [`Mixed::emit_into`] lays them out; the
/// decoder mirrors every field so the layout lives beside its encoder.
/// The default is the state before any upload: attempt zero, nothing
/// granted or held, and no outcome collected.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct UploadState {
    pub(crate) attempt: u16,
    pub(crate) serial: u64,
    pub(crate) base: u32,
    pub(crate) grant: u32,
    /// Source slots a device held.
    pub(crate) held: u16,
    /// The collected outcome's code plus one, or zero before collection.
    pub(crate) outcome: u8,
    pub(crate) bound: bool,
}

impl UploadState {
    /// The state `event` records, or `None` for another kind of event.
    pub(crate) fn of(event: &Event) -> Option<Self> {
        if event.kind != UPLOAD {
            return None;
        }
        let p = &event.payload;
        let word = |at: usize| u32::from_le_bytes(p[at..at + 4].try_into().expect("four bytes"));
        Some(Self {
            attempt: u16::from_le_bytes([p[0], p[1]]),
            serial: u64::from_le_bytes(p[2..10].try_into().expect("eight bytes")),
            base: word(10),
            grant: word(14),
            held: u16::from_le_bytes([p[18], p[19]]),
            outcome: p[20],
            bound: p[21] == 1,
        })
    }

    /// The outcome byte of a collected `outcome`.
    pub(super) fn code(outcome: super::super::upload::UploadOutcome) -> u8 {
        super::upload_code(outcome) as u8 + 1
    }
}

/// A turn's terminal request observation: the result one GET or PUT
/// collection returned to its logical client at an owner during the turn,
/// or that the turn collected more than one. A pending result is no
/// collection. The client is the scene's client index, the mixed scene's
/// spare client 2. [`code`](Self::code) lays it out in a turn record's
/// observation bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Collected {
    /// The turn collected no terminal result.
    #[default]
    Absent,
    Get(u16, u16, super::super::fetch::Outcome),
    Put(u16, u16, super::super::upload::UploadOutcome),
    /// The turn collected two or more results; none is attributed.
    Multiple,
}

impl Collected {
    /// Adds `next`, what the same turn collected after this: an absent
    /// `next` changes nothing, and a second collection is multiple.
    pub(super) fn add(&mut self, next: Self) {
        *self = match (*self, next) {
            (_, Self::Absent) => *self,
            (Self::Absent, next) => next,
            _ => Self::Multiple,
        };
    }

    /// The observation bytes: a variant byte (0 absent, GET 1 complete, 2
    /// missing, 3 pressure, 4 failed, 5 incomplete, PUT 6 published, 7
    /// failed, 8 not started, 9 unknown, 10 multiple), the status as a
    /// little-endian `u16` or zero, then the client and the owner as
    /// little-endian `u16`s, and zero bytes. Absent and multiple are zero
    /// past the variant byte.
    pub(crate) fn code(self) -> [u8; crate::sim::trace::TURN_OBSERVATION] {
        use super::super::fetch::Outcome as Get;
        use super::super::upload::UploadOutcome as Put;
        let (variant, status, client, owner) = match self {
            Self::Absent => (0, None, 0, 0),
            Self::Multiple => (10, None, 0, 0),
            Self::Get(client, owner, outcome) => match outcome {
                Get::Complete => (1, None, client, owner),
                Get::Missing => (2, None, client, owner),
                Get::Pressure(status) => (3, Some(status), client, owner),
                Get::Failed(status) => (4, Some(status), client, owner),
                Get::Incomplete(status) => (5, Some(status), client, owner),
            },
            Self::Put(client, owner, outcome) => match outcome {
                Put::Published => (6, None, client, owner),
                Put::Failed(status) => (7, Some(status), client, owner),
                Put::NotStarted => (8, None, client, owner),
                Put::Unknown => (9, None, client, owner),
            },
        };
        let mut out = [0; crate::sim::trace::TURN_OBSERVATION];
        out[0] = variant;
        out[1..3].copy_from_slice(&status.map_or(0, |status| status as u16).to_le_bytes());
        out[3..5].copy_from_slice(&client.to_le_bytes());
        out[5..7].copy_from_slice(&owner.to_le_bytes());
        out
    }
}
