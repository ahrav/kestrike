//! The link and device outcome audit. Every outcome the simulated link or
//! disk produces other than a plain delivery carries an origin class and a
//! typed reason, and the audit partitions them:
//!
//! - harness: an outcome the harness produced with no origin it can name, or
//!   a scripted fault that could not take effect;
//! - injected: a fault a rule, a fault percentage or a script asked for;
//! - modeled: a bounded resource of the link or device model refusing;
//! - containment-control: an outcome a negative control provokes on purpose
//!   (a premature transmit return and the source bytes it lets change, a
//!   duplicate device completion, an unsupported corruption), excluded from
//!   witnesses;
//! - production-defect: an outcome production code provokes (a wrong peer,
//!   an oversize datagram, a source it cannot hold, a device range the device
//!   cannot serve, source bytes changed while the device held them).
//!
//! A harness record fails the audit, and so does a production-defect record
//! unless the profile declared its reason, which then judges as modeled.
//! Records are bounded: past the bound the audit keeps every record it took,
//! remembers the first unkept harness or production-defect record of each
//! reason, and otherwise reports the overflow as inconclusive. A caller that
//! has read the records may retire the passing ones; the failing records
//! stay, and the remembered failures move into the room retirement frees,
//! so the verdict still names the first failure.

use crate::storage::RefusalReason;
use crate::storage::device::sim::{Event, Injection, Omission, Origin};
use crate::storage::owner_fixture::SimControl;

use super::rules::{Bound, Corruption};

/// An outcome's origin class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    Harness,
    Injected,
    Modeled,
    Containment,
    Production,
}

impl Class {
    /// Every class, in discriminant order.
    pub(crate) const ALL: [Self; 5] = [
        Self::Harness,
        Self::Injected,
        Self::Modeled,
        Self::Containment,
        Self::Production,
    ];

    /// Whether a record of this class fails the audit's verdict.
    pub(crate) fn failing(self) -> bool {
        matches!(self, Self::Harness | Self::Production)
    }
}

/// What an outcome was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reason {
    /// The direction's loss fault dropped the message.
    Lost,
    /// The message belonged to the burst an earlier loss drew.
    LostBurst,
    /// The direction's resend loss dropped the message, whose resend key matches one the link carried before toward
    /// that end.
    LostResend,
    /// A rule dropped the message.
    RuleDrop,
    /// An isolating rule dropped the message.
    Isolated,
    Duplicated,
    Stale,
    Delayed,
    Reordered,
    /// A truncation fault, or a datagram longer than the receive buffer.
    Truncated,
    Corrupted(Corruption),
    /// A corruption whose byte lies past the frame the rules read, which
    /// changed nothing.
    Inapplicable(Corruption),
    WouldBlock,
    CallFailed,
    /// A dead end sent or was sent to.
    DeadEnd,
    /// The receiving ring had no posted buffer.
    Missed,
    /// A reservation would pass this bound; the accepted prefix ended there.
    Full(Bound),
    ForeignPeer,
    Oversize,
    /// A retained source could not be held.
    NotHoldable,
    /// A transmit reference returned before the device read it.
    PrematureReturn,
    /// Source bytes changed between send and the device's read at delivery.
    Altered,
    /// A device refusal by its origin and reason.
    DeviceRefused(Origin, RefusalReason),
    /// A completion the device did not produce.
    DeviceInjected(Injection),
    /// A command a scripted fault lost.
    DeviceLost,
    /// A completion a scripted omission withholds while its command stays pending.
    DeviceOmitted(Omission),
    /// A `Stopped` quiesce answer with commands still pending.
    DeviceFalseStopped,
    /// A scripted failure the harness named no origin for.
    Unattributed,
}

/// Where an outcome happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    /// The link actor, toward one of its ends.
    Link {
        actor: u16,
        toward: usize,
    },
    Device(u16),
}

/// One audited outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Record {
    pub(crate) class: Class,
    pub(crate) reason: Reason,
    pub(crate) source: Source,
}

/// The audit's judgment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Pass,
    /// The first record that fails the world.
    Fail(Record),
    /// Every record passes, and a bound was passed.
    Inconclusive(Bound),
}

impl Verdict {
    /// This verdict joined with a later one: the first failure, else the
    /// first inconclusive bound, else a pass.
    pub(crate) fn then(self, later: Self) -> Self {
        match (self, later) {
            (Self::Fail(_), _) | (Self::Inconclusive(_), Self::Pass | Self::Inconclusive(_)) => {
                self
            }
            _ => later,
        }
    }
}

/// A bounded log of audited outcomes.
#[derive(Debug, Clone, Default)]
pub(crate) struct Audit {
    records: Vec<Record>,
    limit: usize,
    overflow: bool,
    /// Harness and production-defect records past the bound: the first of
    /// each class and reason, so a verdict still sees them.
    unkept: Vec<Record>,
}

/// The class and reason of a device event the audit records, or `None` for
/// a plain one: model refusals of a range as production defects and of
/// anything else as modeled, scripted refusals and lost commands as
/// injected, foreign completions as injected and duplicate completions as
/// containment controls.
pub(crate) fn device_outcome(event: &Event) -> Option<(Class, Reason)> {
    Some(match *event {
        Event::Refused { reason, origin, .. } => {
            let class = match (origin, reason) {
                (Origin::Model, RefusalReason::InvalidRange) => Class::Production,
                (Origin::Model, _) => Class::Modeled,
                (Origin::Script, _) => Class::Injected,
            };
            (class, Reason::DeviceRefused(origin, reason))
        }
        Event::Injected(_, Injection::Duplicate) => (
            Class::Containment,
            Reason::DeviceInjected(Injection::Duplicate),
        ),
        Event::Injected(_, injection) => (Class::Injected, Reason::DeviceInjected(injection)),
        Event::Lost(_) => (Class::Injected, Reason::DeviceLost),
        Event::Omitted(_, Omission::Episode) => {
            (Class::Injected, Reason::DeviceOmitted(Omission::Episode))
        }
        Event::Landed { .. } => (Class::Injected, Reason::DeviceOmitted(Omission::Episode)),
        Event::Omitted(_, Omission::Hostile) => {
            (Class::Containment, Reason::DeviceOmitted(Omission::Hostile))
        }
        Event::FalseStopped => (Class::Containment, Reason::DeviceFalseStopped),
        _ => return None,
    })
}

impl Audit {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            ..Self::default()
        }
    }

    /// Records one outcome; past the bound it records the overflow, keeping
    /// the first harness or production-defect record of each reason.
    pub(crate) fn note(&mut self, class: Class, reason: Reason, source: Source) {
        let record = Record {
            class,
            reason,
            source,
        };
        if self.records.len() < self.limit {
            self.records.push(record);
            return;
        }
        self.overflow = true;
        let failing = class.failing();
        let seen = self
            .unkept
            .iter()
            .any(|kept| kept.class == class && kept.reason == reason);
        if failing && !seen {
            self.unkept.push(record);
        }
    }

    pub(crate) fn records(&self) -> &[Record] {
        &self.records
    }

    /// Drops the passing records at or after `from`, once a caller has
    /// read them, and keeps every harness or production-defect record for
    /// the verdict; returns how many records remain. The records before
    /// `from` are the failing ones an earlier call kept. The failing
    /// records noted past the bound move into the room the drop makes, in
    /// their order, so the verdict names the first failure. A caller that
    /// retires what it read keeps the record list bounded by what one
    /// interval adds, so a long run never passes the bound on passing
    /// records alone.
    pub(crate) fn retire(&mut self, from: usize) -> usize {
        let from = from.min(self.records.len());
        let mut kept = from;
        for at in from..self.records.len() {
            let record = self.records[at];
            if record.class.failing() {
                self.records[kept] = record;
                kept += 1;
            }
        }
        self.records.truncate(kept);
        let room = self.limit.saturating_sub(kept).min(self.unkept.len());
        self.records.extend(self.unkept.drain(..room));
        self.records.len()
    }

    /// How many kept records have `reason`.
    pub(crate) fn count(&self, reason: Reason) -> usize {
        self.records
            .iter()
            .filter(|record| record.reason == reason)
            .count()
    }

    /// How many kept records of `source` have `reason`.
    pub(crate) fn count_at(&self, source: Source, reason: Reason) -> usize {
        self.records
            .iter()
            .filter(|record| record.source == source && record.reason == reason)
            .count()
    }

    /// Records the outcomes of the events device `device`'s log appended
    /// since `seen`, its count of events logged over its life, and moves
    /// `seen` past them. A caller that absorbs after every action keeps
    /// every event however long the run; events the log dropped before this
    /// call read them are an overflow. `seen` counts events since the log's
    /// last [`SimControl::rebase`]; a cursor past [`SimControl::logged`] is
    /// an overflow too, and the call then reads every event the log holds.
    pub(crate) fn absorb_since(&mut self, control: &SimControl, device: u16, seen: &mut u64) {
        let logged = control.logged();
        if logged == *seen {
            return;
        }
        if *seen > logged {
            self.overflow = true;
            *seen = 0;
        }
        let events = control.events();
        let first = control.evicted();
        self.overflow |= first > *seen;
        for (at, event) in events.iter().enumerate() {
            if first + at as u64 >= *seen
                && let Some((class, reason)) = device_outcome(event)
            {
                self.note(class, reason, Source::Device(device));
            }
        }
        *seen = first + events.len() as u64;
    }

    /// Records the outcomes of device `device`'s event log through
    /// [`device_outcome`], once, at the end of a run. A log that dropped
    /// events to make room is an overflow.
    pub(crate) fn absorb(&mut self, control: &SimControl, device: u16) {
        self.absorb_since(control, device, &mut 0);
    }

    /// The class `record` judges as: a production-defect record whose
    /// reason the profile declared judges as modeled.
    pub(crate) fn judged(record: &Record, declared: &[Reason]) -> Class {
        match record.class {
            Class::Production if declared.contains(&record.reason) => Class::Modeled,
            class => class,
        }
    }

    /// Fails on the first harness or undeclared production-defect record,
    /// kept or not; otherwise inconclusive when a bound was passed, else
    /// passes.
    pub(crate) fn verdict(&self, declared: &[Reason]) -> Verdict {
        let failing = self
            .records
            .iter()
            .chain(&self.unkept)
            .find(|record| Self::judged(record, declared).failing());
        match failing {
            Some(record) => Verdict::Fail(*record),
            None if self.overflow => Verdict::Inconclusive(Bound::Records),
            None => Verdict::Pass,
        }
    }
}
