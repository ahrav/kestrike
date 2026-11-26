//! The per-cut stage ledger a recovery run records as `LEDGER` events and
//! inspection and replay [rebuild]. Each cut records a prefix of Planned,
//! Reached, Activated, Recovered and Checked. Skipped ends the prefix after
//! Planned or Reached. A campaign credits only when the bundle's recovery record matches this
//! executable's, every required cut at a decided site is checked Pass and
//! the Restart obligation fired.
//!
//! The ledger rides in the bundle's event vocabulary beside the world's
//! own events, so a replay that reproduces the bundle reproduces the
//! ledger, and the terminal's eight-bit obligation masks stay as they are.

use std::collections::BTreeMap;

use crate::oracle::Obligation;

use super::cut::{Class, Cut, Descriptor, Site};
use super::recovery::{Mismatch, Recovery};
use super::trace::{Event, Loaded, Outcome, PAYLOAD, Terminal, admitted, bit, recorded_profile};

/// The event kind of a ledger entry, after the mixed world's eight kinds.
pub(crate) const LEDGER: u8 = 9;

/// A cut's stages, in the order a cut advances through them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Stage {
    Planned = 1,
    Reached = 2,
    Activated = 3,
    Recovered = 4,
    Checked = 5,
    /// The run declined the cut: its next stage would pass a declared
    /// bound.
    Skipped = 6,
}

impl Stage {
    const ALL: [Self; 6] = [
        Self::Planned,
        Self::Reached,
        Self::Activated,
        Self::Recovered,
        Self::Checked,
        Self::Skipped,
    ];
}

/// What an activation measured: the landing per held write as read back
/// from the media, whether the dead queue was seen drained with no command
/// pending, the custody the dead incarnation held, the failure class whose
/// path the world ran, the device queue's outstanding commands at death,
/// and how the held writes matched the cut's children and the media
/// comparison attributed their blocks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Activation {
    pub(crate) landing: Vec<u64>,
    pub(crate) drained: bool,
    pub(crate) held: u16,
    pub(crate) class: Class,
    pub(crate) queue: u16,
    pub(crate) evidence: Evidence,
}

/// How an activation's measured landing relates to the commands it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Evidence {
    /// Each held write is one of the cut's children and every compared
    /// block's landing is attributed to one write.
    Attributed = 0,
    /// A compared block's landing is ambiguous: its submitted bytes equal
    /// the media before death, a later write overwrote it, or it reads as
    /// neither the old nor the submitted bytes.
    Ambiguous = 1,
    /// The held writes the device captured differ from the children the
    /// descriptor declares at the cut's boundary.
    Unmatched = 2,
}

/// How a cut's recovery check ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Checked {
    Pass = 1,
    Fail = 2,
}

/// One ledger entry: a stage and what it carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Entry {
    Planned,
    /// The cut's boundary stands, with `queue` device commands outstanding.
    Reached {
        queue: u16,
    },
    Activated(Activation),
    Recovered,
    Checked(Checked),
    Skipped,
}

impl Entry {
    pub(crate) fn stage(&self) -> Stage {
        match self {
            Self::Planned => Stage::Planned,
            Self::Reached { .. } => Stage::Reached,
            Self::Activated(_) => Stage::Activated,
            Self::Recovered => Stage::Recovered,
            Self::Checked(_) => Stage::Checked,
            Self::Skipped => Stage::Skipped,
        }
    }
}

/// The most landing words an activation entry carries, the payload left
/// after its fixed fields.
const MAX_LANDING: usize = (PAYLOAD - 12) / 8;

/// The `LEDGER` event for `entry` of cut `cut`: the stage code, the cut
/// index little-endian, then for a reach its queue count little-endian,
/// for an activation the class, the queue and held counts little-endian,
/// the landing word count, the drained flag in bit 0 with the evidence
/// code above it, and each landing word little-endian, and for a check its
/// verdict code.
///
/// # Panics
///
/// When an activation lands more children than [`MAX_LANDING`].
pub(crate) fn event(cut: u32, entry: &Entry) -> Event {
    let mut payload = [0; PAYLOAD];
    payload[0] = entry.stage() as u8;
    payload[1..5].copy_from_slice(&cut.to_le_bytes());
    match entry {
        Entry::Activated(activation) => {
            assert!(activation.landing.len() <= MAX_LANDING, "{activation:?}");
            payload[5] = activation.class as u8;
            payload[6..8].copy_from_slice(&activation.queue.to_le_bytes());
            payload[8..10].copy_from_slice(&activation.held.to_le_bytes());
            payload[10] = activation.landing.len() as u8;
            payload[11] = u8::from(activation.drained) | (activation.evidence as u8) << 1;
            for (at, word) in activation.landing.iter().enumerate() {
                payload[12 + 8 * at..20 + 8 * at].copy_from_slice(&word.to_le_bytes());
            }
        }
        Entry::Reached { queue } => payload[5..7].copy_from_slice(&queue.to_le_bytes()),
        Entry::Checked(checked) => payload[5] = *checked as u8,
        _ => {}
    }
    Event {
        kind: LEDGER,
        payload,
    }
}

/// Why a ledger does not rebuild from a run's events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LedgerError {
    /// Event `at` carries a stage, class, verdict or evidence code the
    /// ledger does not name, or a landing count past [`MAX_LANDING`].
    Malformed { at: usize },
    /// Cut `cut` names no entry of the cut table.
    Unknown { cut: u32 },
    /// Cut `cut` reached `stage` out of order: before its previous stage,
    /// a second time, after it ended, or while another reached cut had not
    /// ended.
    Order { cut: u32, stage: Stage },
}

/// What one cut reached.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Progress {
    pub(crate) stages: Vec<Stage>,
    /// The device commands outstanding when the cut was reached.
    pub(crate) reached: Option<u16>,
    pub(crate) activation: Option<Activation>,
    pub(crate) checked: Option<Checked>,
}

/// Every cut's progress, by cut index.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Ledger {
    pub(crate) cuts: BTreeMap<u32, Progress>,
}

impl Ledger {
    /// Window coverage pairs each progress record with the cut at the same table index.
    pub(super) fn covers(&self, at: u32, cut: &Cut) -> bool {
        self.cuts.get(&at).is_some_and(|progress| {
            progress.checked == Some(Checked::Pass)
                && progress
                    .activation
                    .as_ref()
                    .is_some_and(|a| measured(a, cut, at).is_none())
        })
    }
}

fn decode(at: usize, event: &Event) -> Result<(u32, Entry), LedgerError> {
    let p = &event.payload;
    let malformed = LedgerError::Malformed { at };
    let stage = Stage::ALL
        .into_iter()
        .find(|stage| *stage as u8 == p[0])
        .ok_or(malformed)?;
    let cut = u32::from_le_bytes(p[1..5].try_into().expect("four bytes"));
    let entry = match stage {
        Stage::Planned => Entry::Planned,
        Stage::Reached => Entry::Reached {
            queue: u16::from_le_bytes([p[5], p[6]]),
        },
        Stage::Recovered => Entry::Recovered,
        Stage::Skipped => Entry::Skipped,
        Stage::Checked => Entry::Checked(match p[5] {
            1 => Checked::Pass,
            2 => Checked::Fail,
            _ => return Err(malformed),
        }),
        Stage::Activated => {
            let class = Class::ALL
                .into_iter()
                .find(|class| *class as u8 == p[5])
                .ok_or(malformed)?;
            let words = usize::from(p[10]);
            if words > MAX_LANDING {
                return Err(malformed);
            }
            let landing = (0..words)
                .map(|at| {
                    u64::from_le_bytes(p[12 + 8 * at..20 + 8 * at].try_into().expect("eight bytes"))
                })
                .collect();
            let evidence = match p[11] >> 1 {
                0 => Evidence::Attributed,
                1 => Evidence::Ambiguous,
                2 => Evidence::Unmatched,
                _ => return Err(malformed),
            };
            Entry::Activated(Activation {
                landing,
                drained: p[11] & 1 == 1,
                held: u16::from_le_bytes([p[8], p[9]]),
                class,
                queue: u16::from_le_bytes([p[6], p[7]]),
                evidence,
            })
        }
    };
    Ok((cut, entry))
}

/// The ledger `events` record over a table of `cuts` entries: each cut's
/// stages from its `LEDGER` events, which must start with `Planned` and
/// follow the stage order once each, a skip ending the cut after its
/// planning or reach.
///
/// # Errors
///
/// As [`LedgerError`], for the first event that breaks the rules.
pub(crate) fn rebuild(events: &[Event], cuts: u32) -> Result<Ledger, LedgerError> {
    let mut ledger = Ledger::default();
    // The reached cut whose stages have not ended; one cut runs at a time.
    let mut open: Option<u32> = None;
    for (at, event) in events.iter().enumerate().filter(|(_, e)| e.kind == LEDGER) {
        let (cut, entry) = decode(at, event)?;
        if cut >= cuts {
            return Err(LedgerError::Unknown { cut });
        }
        let stage = entry.stage();
        let progress = ledger.cuts.entry(cut).or_default();
        let follows = matches!(
            (progress.stages.last(), stage),
            (None, Stage::Planned)
                | (Some(Stage::Planned), Stage::Reached)
                | (Some(Stage::Reached), Stage::Activated)
                | (Some(Stage::Activated), Stage::Recovered)
                | (Some(Stage::Recovered), Stage::Checked)
                | (Some(Stage::Planned | Stage::Reached), Stage::Skipped)
        );
        let interleaved = stage == Stage::Reached && open.is_some_and(|other| other != cut);
        if !follows || interleaved {
            return Err(LedgerError::Order { cut, stage });
        }
        match stage {
            Stage::Reached => open = Some(cut),
            Stage::Checked | Stage::Skipped if open == Some(cut) => open = None,
            _ => {}
        }
        progress.stages.push(stage);
        match entry {
            Entry::Reached { queue } => progress.reached = Some(queue),
            Entry::Activated(activation) => progress.activation = Some(activation),
            Entry::Checked(checked) => progress.checked = Some(checked),
            _ => {}
        }
    }
    Ok(ledger)
}

/// Why a campaign earns no credit, naming the cut that withholds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Gap {
    /// A required cut the run never planned.
    Omitted { cut: u32 },
    /// A required cut the run skipped at a declared bound.
    Bound { cut: u32 },
    /// A required cut planned and never reached.
    Unreached { cut: u32 },
    /// A required cut reached and never checked.
    Unchecked { cut: u32 },
    /// A required cut whose captured held writes differ from the children
    /// its descriptor declares.
    Unmatched { cut: u32 },
    /// A required cut whose media comparison left a block's landing
    /// ambiguous.
    Ambiguous { cut: u32 },
    /// A required cut whose measured landing differs from the mask it
    /// prescribes.
    Landing { cut: u32 },
    /// A required cut activated under a class other than its own.
    Class { cut: u32 },
    /// A required cut whose dead queue was not seen drained.
    Undrained { cut: u32 },
    /// A required cut whose check failed.
    Failed { cut: u32 },
    /// A required cut at an [`UNDECIDED`] site, whose recovery outcome
    /// depends on a replacement and protected-exclusion decision the
    /// recovery contract has not accepted.
    Undecided { cut: u32 },
    /// No Restart obligation fired.
    NoRestart,
}

/// The sites whose recovery outcome depends on the replacement decision
/// and protected-exclusion semantics, which stay unaccepted.
pub(crate) const UNDECIDED: [Site; 2] = [Site::Exclusion, Site::Successor];

/// A campaign's credit over `table`, `descriptor`'s cut table: every
/// required cut, in table order, must be planned, reached, activated,
/// recovered and checked Pass, at a site outside [`UNDECIDED`], with an
/// activation whose held writes match the cut's children, whose media
/// comparison attributed every block, whose measured landing equals the
/// cut's mask, whose class is the cut's and whose dead queue drained, each
/// judged once the cut activated; and the Restart obligation must have
/// fired (`restart`).
///
/// # Errors
///
/// The first required cut's [`Gap`], else [`Gap::NoRestart`].
pub(crate) fn credit(
    ledger: &Ledger,
    table: &[Cut],
    descriptor: &Descriptor,
    restart: bool,
) -> Result<(), Gap> {
    for (at, cut) in table.iter().enumerate() {
        if !descriptor.requires(cut.site) {
            continue;
        }
        let at = at as u32;
        let undecided = UNDECIDED.iter().any(|site| *site as u16 == cut.site);
        let Some(progress) = ledger.cuts.get(&at) else {
            return Err(Gap::Omitted { cut: at });
        };
        let reached = |stage| progress.stages.contains(&stage);
        let gap = if undecided {
            Some(Gap::Undecided { cut: at })
        } else if reached(Stage::Skipped) {
            Some(Gap::Bound { cut: at })
        } else if !reached(Stage::Reached) {
            Some(Gap::Unreached { cut: at })
        } else if let Some(gap) = progress
            .activation
            .as_ref()
            .and_then(|activation| measured(activation, cut, at))
        {
            Some(gap)
        } else if !reached(Stage::Checked) {
            Some(Gap::Unchecked { cut: at })
        } else if progress.checked != Some(Checked::Pass) {
            Some(Gap::Failed { cut: at })
        } else {
            None
        };
        if let Some(gap) = gap {
            return Err(gap);
        }
    }
    if restart { Ok(()) } else { Err(Gap::NoRestart) }
}

/// The first way `activation` falls short of cut `at`'s plan, `cut`.
fn measured(activation: &Activation, cut: &Cut, at: u32) -> Option<Gap> {
    match activation.evidence {
        Evidence::Unmatched => Some(Gap::Unmatched { cut: at }),
        Evidence::Ambiguous => Some(Gap::Ambiguous { cut: at }),
        Evidence::Attributed if activation.landing != cut.mask => Some(Gap::Landing { cut: at }),
        Evidence::Attributed if activation.class != cut.class => Some(Gap::Class { cut: at }),
        Evidence::Attributed if !activation.drained => Some(Gap::Undrained { cut: at }),
        Evidence::Attributed => None,
    }
}

/// Whether `events` leave a cut armed: its last ledger entry among them
/// is `Reached`, or `None` when they hold no ledger entry.
pub(crate) fn armed(events: &[Event]) -> Option<bool> {
    let (at, event) = events
        .iter()
        .enumerate()
        .rev()
        .find(|(_, event)| event.kind == LEDGER)?;
    Some(decode(at, event).is_ok_and(|(_, entry)| entry.stage() == Stage::Reached))
}

/// Whether `loaded`'s run counts: its terminal counts and, for a recovery
/// bundle, its campaign credits. Every form that judges a bundle counts
/// through this.
pub(crate) fn counts(loaded: &Loaded) -> bool {
    loaded.terminal.counts() && campaign(loaded).is_none_or(|verdict| verdict == Campaign::Credited)
}

/// A recovery bundle's campaign verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Campaign {
    Credited,
    Inconclusive(Gap),
    /// The ledger does not rebuild from the bundle's events.
    Refused(LedgerError),
    /// The bundle's Config holds no recovery record.
    Unrecorded,
    /// The bundle's recovery record differs from the one this executable
    /// derives for the profile, in its first differing field.
    Mismatched(Mismatch),
}

/// The campaign verdict of `loaded`, a bundle of a recovery profile, over
/// its profile's cut table, with the Restart obligation fired when the
/// terminal is a complete pass whose fired mask holds it; `None` for a
/// live bundle. The bundle's recovery record must match the one this
/// executable derives, as a replay requires, so the ledger is judged
/// against the cut table it was recorded under.
pub(crate) fn campaign(loaded: &Loaded) -> Option<Campaign> {
    let recovery = recorded_profile(&loaded.fields).and_then(Recovery::named)?;
    let Ok(Some(record)) = admitted(&loaded.fields) else {
        return Some(Campaign::Unrecorded);
    };
    if let Err(mismatch) = record.check(&recovery.record()) {
        return Some(Campaign::Mismatched(mismatch));
    }
    let table = recovery.table();
    let ledger = match rebuild(&loaded.events, table.len() as u32) {
        Ok(ledger) => ledger,
        Err(error) => return Some(Campaign::Refused(error)),
    };
    let restart = matches!(
        loaded.terminal,
        Terminal::Complete {
            outcome: Outcome::Pass,
            fired,
            ..
        } if fired & bit(Obligation::Restart) != 0
    );
    Some(
        match credit(&ledger, &table, &recovery.descriptor(), restart) {
            Ok(()) => Campaign::Credited,
            Err(gap) => Campaign::Inconclusive(gap),
        },
    )
}

/// The worker prints these model limits beside the rebuilt stage census.
pub(crate) const LIMITS: &str = "process death, and a controller reset under the torn profile, against a live simulated controller; each cut's landing applied to the captured held writes, executed in acceptance order, through drop and torn-write faults and measured on media against the submitted bytes, with the dead queue observed drained or reset; the held writes execute before the reset, so the class names the disposal path that ran and the media of both classes agree; supported landings none, whole and sector prefix; non-prefix sector mixes, volatile-cache loss, timeout callbacks and queue-pair failures outside the profile; sites awaiting the replacement and exclusion decisions stay Inconclusive";

/// Counts cuts at each stage in [`Stage::ALL`] order.
pub(super) fn stage_counts(ledger: &Ledger) -> [usize; 6] {
    Stage::ALL.map(|stage| {
        ledger
            .cuts
            .values()
            .filter(|progress| progress.stages.contains(&stage))
            .count()
    })
}
