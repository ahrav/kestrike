//! The attach gate over the reserving driver: the Register, Acquire and Report gate mints the volume's medium
//! admission only from a Report that shows the own pair as the one holder and the one registrant. A Report that
//! lists one more registrant of another pair, holding nothing, ends the attach `Unfenced(ForeignRegistrant)`: the
//! driver records no medium admission, the device takes no medium command and the readiness word reads
//! `Withheld`. A Report that lists the own pair alone passes: one admission follows the gate's three reservation
//! commands and the root probes are the first medium commands.
//!
//! Each test decides what the attach showed into a value, lets the volume, the storage and the arena go, and
//! asserts afterwards, so a failed assertion unwinds with no fixture alive.

use super::super::device::{Operation, ReservationCommand};
use super::super::readiness::State;
use super::super::recovery::MetadataOutcome;
use super::GateRefusal;
use super::gate_fixture::{
    arena, attach_reserving, bounds_of, foreign, limits, medium, own, ticks,
};
use crate::failover::evidence::{Registrant, Report, ReservationType};

/// The controller ID the reserving driver registers the own host under.
const OWN_CNTLID: u16 = 10;
/// The controller ID of the other host's registration.
const FOREIGN_CNTLID: u16 = 20;
/// Ticks that deliver the gate's three completions and every command that follows them.
const ROUNDS: usize = 32;

/// What one attach over the reserving driver showed once its gate had run.
#[derive(Debug, PartialEq, Eq)]
struct Attach {
    /// The first three reservation commands the driver took.
    gate: Vec<ReservationCommand>,
    outcome: MetadataOutcome,
    readiness: State,
    /// The driver's medium admissions: the reservation commands logged at each, and whether a medium command
    /// preceded it.
    admissions: Vec<(usize, bool)>,
    /// Medium commands the simulated device accepted or refused.
    device_medium: usize,
    /// Reads and writes the volume handed the driver.
    driver_medium: usize,
    /// The device offsets of the reads the simulated device accepted, in submission order.
    reads: Vec<u64>,
    /// The device offsets of the writes the simulated device accepted, in submission order.
    writes: Vec<u64>,
    closed: bool,
}

/// The gate's commands for the own pair: Register with no current key, Acquire under the own key, and the Report
/// at ordinal 3.
fn gate_commands() -> Vec<ReservationCommand> {
    let own = own();
    vec![
        ReservationCommand::Register { new: own.key },
        ReservationCommand::Acquire { current: own.key },
        ReservationCommand::Report { not_before: 3 },
    ]
}

/// Attaches a volume on fresh media under the fixture authority, whose token carries the own pair, with `racing`
/// registered by the device right after the own Acquire succeeds, so the gate's Report lists it beside the own
/// holder. Runs the gate and what follows it, and returns what the attach showed.
fn attach(racing: Option<Registrant>) -> Attach {
    let arena = arena();
    let storage = super::volume_tests::storage(2);
    let (mut volume, control, registry) = attach_reserving(
        &storage,
        &arena,
        crate::storage::ServingAuthority::fixture(),
    );
    registry.borrow_mut().after_acquire = racing;
    ticks(&mut volume, &control, ROUNDS);
    let offsets = |operation| {
        super::bootstrap_tests::submitted(&control, operation)
            .into_iter()
            .map(|(_, start)| start)
            .collect()
    };
    let shown = {
        let registry = registry.borrow();
        Attach {
            gate: registry.log.iter().take(3).copied().collect(),
            outcome: volume.metadata_outcome(),
            readiness: volume.readiness(),
            admissions: registry.admissions.clone(),
            device_medium: medium(&control),
            driver_medium: registry.medium,
            reads: offsets(Operation::Read),
            writes: offsets(Operation::Write),
            closed: storage.is_closed(),
        }
    };
    drop(volume);
    drop(storage);
    drop(arena);
    shown
}

/// The gate's Report shows a type-2 reservation held by the own pair beside one registrant of another pair that
/// holds nothing. The own pair is the one holder but not the one registrant, so the gate mints nothing: the
/// attach ends `Unfenced(ForeignRegistrant)` after the gate's three commands, the driver's medium gate stays
/// shut, no read or write reaches the driver or the device, admission closes and the readiness word reads
/// `Withheld`.
#[test]
fn a_non_holding_registrant_of_another_pair_ends_the_attach_unfenced_with_no_medium_admission() {
    let shown = attach(Some(Registrant {
        cntlid: FOREIGN_CNTLID,
        holder: false,
        pair: foreign(),
    }));
    assert_eq!(
        shown,
        Attach {
            gate: gate_commands(),
            outcome: MetadataOutcome::Unfenced(GateRefusal::ForeignRegistrant),
            readiness: State::Withheld,
            admissions: Vec::new(),
            device_medium: 0,
            driver_medium: 0,
            reads: Vec::new(),
            writes: Vec::new(),
            closed: true,
        },
        "a Report listing another pair as a registrant mints no medium admission"
    );
}

/// The same attach with no other registrant: the gate's Report lists the own pair alone, as the one holder and
/// the one registrant. The gate passes with one admission, taken after its three reservation commands and before
/// any medium command, and the probes of both root slots are the first medium commands; fresh media report
/// `Unformatted` with the readiness word `Loading`.
#[test]
fn the_own_pair_alone_passes_the_gate_with_one_admission_before_the_root_probes() {
    let shown = attach(None);
    assert_eq!(
        shown,
        Attach {
            gate: gate_commands(),
            outcome: MetadataOutcome::Unformatted,
            readiness: State::Loading,
            admissions: vec![(3, false)],
            device_medium: 2,
            driver_medium: 2,
            reads: vec![0, 4096],
            writes: Vec::new(),
            closed: false,
        },
        "the own pair alone passes the gate; the root probes are its first medium commands"
    );
}

/// The gate's verdict on a successful, parsed Report for the own pair, as the pair the minted admission names or
/// the refusal.
fn verdict(entries: &[Registrant]) -> Result<crate::failover::evidence::Pair, GateRefusal> {
    let report = Report {
        submitted_at: 0,
        rtype: ReservationType::ExclusiveAccess,
        regctl: entries.len() as u32,
        entries,
    };
    super::fence::judge(true, &Ok(report), own(), &bounds_of(limits())).map(|fenced| fenced.own())
}

/// The gate's verdict mints the admission for the own pair from a conclusive type-2 Report whose one record is
/// the own holder, and refuses `ForeignRegistrant` once the same Report lists a second record of another pair
/// that holds nothing, whichever record comes first.
#[test]
fn the_gate_verdict_mints_for_the_one_registrant_and_refuses_a_second_pair() {
    let holder = Registrant {
        cntlid: OWN_CNTLID,
        holder: true,
        pair: own(),
    };
    let other = Registrant {
        cntlid: FOREIGN_CNTLID,
        holder: false,
        pair: foreign(),
    };
    let verdicts = [
        verdict(&[holder]),
        verdict(&[holder, other]),
        verdict(&[other, holder]),
    ];
    assert_eq!(
        verdicts,
        [
            Ok(own()),
            Err(GateRefusal::ForeignRegistrant),
            Err(GateRefusal::ForeignRegistrant),
        ],
        "the verdict on the own pair alone, then with another pair's record after and before it"
    );
}
