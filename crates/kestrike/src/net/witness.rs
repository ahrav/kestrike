//! The external witness: what clients observed, recorded outside every
//! owner incarnation. The run's lifecycle owns one bounded witness beside
//! its incarnations, so death, disposal and relaunch leave it as it
//! stands, and no incarnation's storage rebuilds it.
//!
//! For each operation the witness records emission apart from observation.
//! A link tap records emission when a RESULT for the operation stands in
//! the link toward its client; the client's consumption of an outcome under
//! the operation's exact peer, slot, generation and epoch records
//! observation. At a cut each operation is `Observed` once its client
//! consumed the acknowledgment, `Unobserved` once its client consumed
//! another outcome or its client's epoch ended without consuming one, and
//! `Ambiguous` while its response is pending or in flight. Another outcome
//! consumed first, such as `Unknown` after a lost response, records that the
//! client consumed no acknowledgment and applies no effect, and stays
//! resolvable: a later
//! acknowledgment consumed under the same tuple, the delayed RESULT that
//! reports the publication, makes the operation `Observed` and applies its
//! effect once. A cut names the living epoch, so a death changes no
//! recorded content. Only an observed acknowledgment applies its effect: a
//! recovery-safe exclusion of a binding, keyed by the witness's own record
//! of key, label and frozen identity, or a freshness cursor that raises the
//! floor, the highest observed-acknowledged cursor of the invalidation
//! feed.
//!
//! The witness digests its semantic content, records each change as a
//! `OBSERVATION` trace event and rebuilds an equal witness from those
//! events.
//! Past its operation bound it marks itself overflowed and judges
//! Inconclusive. Adapters read it through [`View`]; the run's owner records
//! into it through the lifecycle. Clients live and die with their
//! incarnation, since a death moves them into the dead bundle and a
//! relaunch starts new ones, so the incarnation is the client epoch and a
//! run records consumption only from a living client.

use sha2::{Digest, Sha256};

use crate::oracle::{Decision, DurableFact, Hypothesis, Inconclusive, KeyId, Label, Script};
use crate::sim::trace::{Event, PAYLOAD};

use super::requests::RequestId;

/// The event kind of a witness change, after the stage ledger's kind.
pub(crate) const OBSERVATION: u8 = 10;

/// Operations one witness holds.
pub(crate) const LIMIT: usize = 64;

/// The exact identity a client consumes a response under: its peer, the
/// request's slot and generation, and the client's session epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Tuple {
    pub(crate) peer: u8,
    pub(crate) slot: u16,
    pub(crate) generation: u64,
    pub(crate) epoch: u64,
}

impl Tuple {
    /// The tuple of the request whose wire ID is `wire`.
    pub(crate) fn of_wire(peer: u8, wire: u64, epoch: u64) -> Self {
        let id = RequestId::from_wire(wire);
        Self {
            peer,
            slot: id.slot(),
            generation: id.generation(),
            epoch,
        }
    }
}

/// What an operation's acknowledgment establishes once a client observes
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Effect {
    /// A live acknowledgment: it binds nothing across a crash.
    Live,
    /// A recovery-safe acknowledgment excluding `label` of `key`, whose
    /// binding had frozen identity `frozen`.
    Exclusion {
        key: KeyId,
        label: Label,
        frozen: u64,
    },
    /// An acknowledgment covering the invalidation feed through `cursor`;
    /// `caller` when the cursor comes from the caller's freshness fields.
    Freshness { cursor: u64, caller: bool },
}

/// How an operation stands at a cut.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Class {
    /// Its client consumed the acknowledgment under the exact tuple.
    Observed,
    /// Its client consumed another outcome, or died without consuming one.
    /// A later acknowledgment consumed under the same tuple changes the
    /// operation to `Observed`.
    Unobserved,
    /// Its response is pending or in flight.
    Ambiguous,
}

/// One witness change, as the trace records it, tagged 1 to 4 in
/// declaration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Change {
    /// Operation `op` began under `tuple` with `effect`.
    Began {
        op: u32,
        tuple: Tuple,
        effect: Effect,
    },
    /// A RESULT for `op` stood in the link toward its client.
    Emitted { op: u32 },
    /// A client consumed an outcome under `tuple`, the acknowledgment when
    /// `acknowledged`.
    Consumed { tuple: Tuple, acknowledged: bool },
    /// Operation `op` intends the bytes whose SHA-256 is `digest`.
    Intended { op: u32, digest: [u8; 32] },
}

/// One operation's record: `consumed` holds whether its client consumed
/// the acknowledgment, once it consumed an outcome; `Some(false)` records a
/// consumed outcome other than the acknowledgment, such as `Unknown`, which
/// a later acknowledgment under the same tuple resolves to `Some(true)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Operation {
    op: u32,
    tuple: Tuple,
    effect: Effect,
    intended: Option<[u8; 32]>,
    emitted: bool,
    consumed: Option<bool>,
}

/// What one change does to a witness within its operation bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    /// The witness applied and recorded the change.
    Changed,
    /// The witness and its recorded changes remain unchanged.
    Unchanged,
    /// A beginning names a held operation's ID or tuple with other fields.
    Conflict,
}

/// A recovery-safe exclusion the witness holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Exclusion {
    pub(crate) key: KeyId,
    pub(crate) label: Label,
    pub(crate) frozen: u64,
}

/// The external witness of one run.
#[derive(Clone, Debug, Default)]
pub(crate) struct Witness {
    operations: Vec<Operation>,
    exclusions: Vec<Exclusion>,
    /// The highest observed-acknowledged cursor from the owner's feed.
    owned: Option<u64>,
    /// The highest observed-acknowledged cursor from the caller's freshness
    /// fields.
    claimed: Option<u64>,
    overflow: bool,
    changes: Vec<Change>,
}

impl Witness {
    /// Applies `change` and records it when it changed the witness: a
    /// beginning of an operation it does not hold, the first emission or
    /// intended bytes of a held operation, the first consumption under a
    /// held operation's tuple, or the first acknowledgment consumed under a
    /// held tuple whose client consumed another outcome first. Any other
    /// consumption preserves the witness. The beginning past the operation
    /// bound is recorded and marks the witness overflowed, and the witness
    /// remains fixed after overflow.
    ///
    /// # Panics
    ///
    /// When an operation it holds begins again under another tuple or
    /// effect, or another operation begins under a held tuple.
    pub(crate) fn apply(&mut self, change: Change) {
        if self.overflow {
            return;
        }
        assert!(
            self.step(change) != Step::Conflict,
            "{change:?} begins under a held operation's ID or tuple with other fields"
        );
    }

    /// Applies `change` to a witness within its operation bound and records
    /// `change` when `change` modifies the witness.
    fn step(&mut self, change: Change) -> Step {
        match change {
            Change::Began { op, tuple, effect } => {
                let named = |o: &&Operation| o.op == op || o.tuple == tuple;
                if let Some(held) = self.operations.iter().find(named) {
                    return if (held.op, held.tuple, held.effect) == (op, tuple, effect) {
                        Step::Unchanged
                    } else {
                        Step::Conflict
                    };
                }
                if self.operations.len() == LIMIT {
                    self.overflow = true;
                } else {
                    self.operations.push(Operation {
                        op,
                        tuple,
                        effect,
                        intended: None,
                        emitted: false,
                        consumed: None,
                    });
                }
            }
            Change::Emitted { op } => match self.operations.iter_mut().find(|o| o.op == op) {
                Some(held) if !held.emitted => held.emitted = true,
                _ => return Step::Unchanged,
            },
            Change::Consumed {
                tuple,
                acknowledged,
            } => {
                let Some(held) = self.operations.iter_mut().find(|o| o.tuple == tuple) else {
                    return Step::Unchanged;
                };
                if !matches!(
                    (held.consumed, acknowledged),
                    (None, _) | (Some(false), true)
                ) {
                    return Step::Unchanged;
                }
                held.consumed = Some(acknowledged);
                let effect = held.effect;
                if acknowledged {
                    self.observe(effect);
                }
            }
            Change::Intended { op, digest } => {
                match self.operations.iter_mut().find(|o| o.op == op) {
                    Some(held) if held.intended.is_none() => held.intended = Some(digest),
                    _ => return Step::Unchanged,
                }
            }
        }
        self.changes.push(change);
        Step::Changed
    }

    /// Applies an observed acknowledgment's effect.
    fn observe(&mut self, effect: Effect) {
        match effect {
            Effect::Live => {}
            Effect::Exclusion { key, label, frozen } => {
                let exclusion = Exclusion { key, label, frozen };
                if !self.exclusions.contains(&exclusion) {
                    self.exclusions.push(exclusion);
                }
            }
            Effect::Freshness { cursor, caller } => {
                let highest = if caller {
                    &mut self.claimed
                } else {
                    &mut self.owned
                };
                *highest = (*highest).max(Some(cursor));
            }
        }
    }

    /// The witness the recorded `events` rebuild; events of other kinds
    /// pass by.
    ///
    /// # Errors
    ///
    /// The position of the first `OBSERVATION` event that decodes to no
    /// change or to one that changes nothing, such as a consumption of an
    /// operation that never began, or to a beginning that conflicts with a
    /// held operation's ID or tuple.
    pub(crate) fn rebuild(events: &[Event]) -> Result<Self, usize> {
        let mut witness = Self::default();
        for (at, event) in events.iter().enumerate() {
            if event.kind == OBSERVATION {
                let change = decode(&event.payload).ok_or(at)?;
                if witness.overflow || witness.step(change) != Step::Changed {
                    return Err(at);
                }
            }
        }
        Ok(witness)
    }

    /// Every change, in order, as `OBSERVATION` trace events.
    pub(crate) fn events(&self) -> Vec<Event> {
        self.changes.iter().map(encode).collect()
    }

    pub(crate) fn view(&self) -> View<'_> {
        View(self)
    }
}

/// A read-only view of a witness, which adapters hold.
#[derive(Clone, Copy, Debug)]
pub(crate) struct View<'w>(&'w Witness);

impl View<'_> {
    /// How operation `op` stands at a cut whose living client epoch is
    /// `living`, if the witness holds it and stayed within its bound; an
    /// overflowed witness classifies nothing.
    pub(crate) fn class(&self, op: u32, living: Option<u64>) -> Option<Class> {
        if self.0.overflow {
            return None;
        }
        self.operation(op).map(|o| match o.consumed {
            Some(true) => Class::Observed,
            Some(false) => Class::Unobserved,
            None if living != Some(o.tuple.epoch) => Class::Unobserved,
            None => Class::Ambiguous,
        })
    }

    /// Whether a RESULT for `op` was emitted toward its client.
    pub(crate) fn emitted(&self, op: u32) -> bool {
        self.operation(op).is_some_and(|o| o.emitted)
    }

    /// The SHA-256 of the bytes `op` intended, once recorded.
    pub(crate) fn intended(&self, op: u32) -> Option<[u8; 32]> {
        self.operation(op).and_then(|o| o.intended)
    }

    fn operation(&self, op: u32) -> Option<&Operation> {
        self.0.operations.iter().find(|o| o.op == op)
    }

    pub(crate) fn exclusions(&self) -> &[Exclusion] {
        &self.0.exclusions
    }

    /// The highest observed-acknowledged freshness cursor; 0 before any.
    pub(crate) fn floor(&self) -> u64 {
        self.0.owned.max(self.0.claimed).unwrap_or(0)
    }

    /// The floor rests on the caller's freshness fields: the caller's
    /// highest cursor exceeds the owner's, so an equal owner cursor wins.
    fn caller(&self) -> bool {
        self.0.claimed > self.0.owned
    }

    /// The SHA-256 of the witness's semantic content: every operation's ID,
    /// tuple, effect, intended bytes, emission and consumption, the
    /// exclusions, each source's highest cursor and the overflow mark.
    pub(crate) fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update((self.0.operations.len() as u64).to_le_bytes());
        for operation in &self.0.operations {
            hash.update(operation.op.to_le_bytes());
            hash.update(tuple_bytes(operation.tuple));
            hash.update(effect_bytes(operation.effect));
            hash.update(operation.intended.unwrap_or_default());
            hash.update([u8::from(operation.intended.is_some())]);
            let consumed = operation.consumed.map_or(0, |ack| 1 + u8::from(ack));
            hash.update([u8::from(operation.emitted), consumed]);
        }
        for exclusion in &self.0.exclusions {
            hash.update(effect_bytes(Effect::Exclusion {
                key: exclusion.key,
                label: exclusion.label,
                frozen: exclusion.frozen,
            }));
        }
        for cursor in [self.0.owned, self.0.claimed] {
            hash.update(cursor.unwrap_or(0).to_le_bytes());
            hash.update([u8::from(cursor.is_some())]);
        }
        hash.update([u8::from(self.0.overflow)]);
        hash.finalize().into()
    }

    /// Records the witness's facts and a Restart row for `key` into `rows`
    /// under `hypothesis`: each exclusion as a recovery-safe exclusion fact
    /// with its frozen identity, and, for each of `served` whose recovery
    /// replayed the invalidation feed through `replayed`, freshness and
    /// invalidation-replay facts once `replayed` reaches the floor. A floor
    /// resting on the caller's freshness fields records each served label's
    /// freshness fact with `Decision::CallerFreshness` open once `replayed`
    /// reaches the owner's highest cursor.
    ///
    /// # Errors
    ///
    /// The witness overflowed its operation bound.
    pub(crate) fn feed(
        &self,
        rows: &mut Script,
        hypothesis: Hypothesis,
        (key, served): (KeyId, &[Label]),
        replayed: u64,
    ) -> Result<(), Inconclusive> {
        if self.0.overflow {
            return Err(Inconclusive::DomainBound {
                dimension: "witness operations",
                limit: LIMIT,
                observed: LIMIT + 1,
            });
        }
        for exclusion in &self.0.exclusions {
            rows.exclusion(hypothesis, exclusion.key, exclusion.label, exclusion.frozen);
        }
        let owned = self.0.owned.unwrap_or(0);
        for &label in served {
            if replayed >= owned {
                if self.caller() {
                    let open = Decision::CallerFreshness;
                    rows.open_fact(hypothesis, (key, label), DurableFact::Freshness, open);
                } else {
                    rows.fact(hypothesis, key, label, DurableFact::Freshness);
                }
            }
            if replayed >= self.floor() {
                rows.fact(hypothesis, key, label, DurableFact::InvalidationReplayed);
            }
        }
        rows.restart(hypothesis, key);
        Ok(())
    }
}

fn tuple_bytes(tuple: Tuple) -> [u8; 19] {
    let mut out = [0; 19];
    out[0] = tuple.peer;
    out[1..3].copy_from_slice(&tuple.slot.to_le_bytes());
    out[3..11].copy_from_slice(&tuple.generation.to_le_bytes());
    out[11..19].copy_from_slice(&tuple.epoch.to_le_bytes());
    out
}

fn tuple_of(bytes: &[u8]) -> Tuple {
    let word = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8 bytes"));
    Tuple {
        peer: bytes[0],
        slot: u16::from_le_bytes([bytes[1], bytes[2]]),
        generation: word(3),
        epoch: word(11),
    }
}

/// An effect as 18 bytes: a tag, then the exclusion's key, label and
/// frozen identity, or the freshness cursor and its caller flag.
fn effect_bytes(effect: Effect) -> [u8; 18] {
    let mut out = [0; 18];
    match effect {
        Effect::Live => {}
        Effect::Exclusion { key, label, frozen } => {
            out[0] = 1;
            out[1] = key.0;
            out[2..10].copy_from_slice(&label.0.to_le_bytes());
            out[10..18].copy_from_slice(&frozen.to_le_bytes());
        }
        Effect::Freshness { cursor, caller } => {
            out[0] = 2;
            out[1..9].copy_from_slice(&cursor.to_le_bytes());
            out[9] = u8::from(caller);
        }
    }
    out
}

fn effect_of(bytes: &[u8]) -> Option<Effect> {
    let word = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8 bytes"));
    match bytes[0] {
        0 => Some(Effect::Live),
        1 => Some(Effect::Exclusion {
            key: KeyId(bytes[1]),
            label: Label(word(2)),
            frozen: word(10),
        }),
        2 if bytes[9] <= 1 => Some(Effect::Freshness {
            cursor: word(1),
            caller: bytes[9] == 1,
        }),
        _ => None,
    }
}

/// `change` as an `OBSERVATION` event: a tag, then the operation, tuple and
/// effect of a beginning, the operation and digest of intended bytes, the
/// operation of an emission, or the tuple and acknowledgment flag of a
/// consumption.
fn encode(change: &Change) -> Event {
    let mut payload = [0; PAYLOAD];
    match *change {
        Change::Began { op, tuple, effect } => {
            payload[0] = 1;
            payload[1..5].copy_from_slice(&op.to_le_bytes());
            payload[5..24].copy_from_slice(&tuple_bytes(tuple));
            payload[24..42].copy_from_slice(&effect_bytes(effect));
        }
        Change::Emitted { op } => {
            payload[0] = 2;
            payload[1..5].copy_from_slice(&op.to_le_bytes());
        }
        Change::Consumed {
            tuple,
            acknowledged,
        } => {
            payload[0] = 3;
            payload[1..20].copy_from_slice(&tuple_bytes(tuple));
            payload[20] = u8::from(acknowledged);
        }
        Change::Intended { op, digest } => {
            payload[0] = 4;
            payload[1..5].copy_from_slice(&op.to_le_bytes());
            payload[5..37].copy_from_slice(&digest);
        }
    }
    Event {
        kind: OBSERVATION,
        payload,
    }
}

/// The change an `OBSERVATION` event's payload encodes, or `None` for an unknown
/// tag, effect or flag, or a payload whose encoding differs.
fn decode(payload: &[u8; PAYLOAD]) -> Option<Change> {
    let op = u32::from_le_bytes(payload[1..5].try_into().expect("4 bytes"));
    let change = match payload[0] {
        1 => Change::Began {
            op,
            tuple: tuple_of(&payload[5..24]),
            effect: effect_of(&payload[24..42])?,
        },
        2 => Change::Emitted { op },
        3 => Change::Consumed {
            tuple: tuple_of(&payload[1..20]),
            acknowledged: payload[20] == 1,
        },
        4 => Change::Intended {
            op,
            digest: payload[5..37].try_into().expect("32 bytes"),
        },
        _ => return None,
    };
    (encode(&change).payload == *payload).then_some(change)
}
