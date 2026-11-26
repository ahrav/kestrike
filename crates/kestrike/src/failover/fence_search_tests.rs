use super::evidence::NotSole;
use super::fence_search::{
    Action, DECISIONS, Fence, KINDS, Plant, RECORD_DECISIONS, ROOT, Reply, WITNESSES,
};
use super::retire::Target;
use super::search::{End, Model, Replay, Seen, Totals, Verdict, control, replay, search};
use super::tenure_search::{
    self as tenure, Action as RecordAction, COPIED, Plant as RecordPlant, Records, Side,
};
use crate::storage::store::sim::Arm;

const CAP: u64 = 1_000_000;

/// The totals of the unplanted fence search at `fence_search::BOUND`: highest `E` 3, no lost or parked reply, and
/// two designations, one spent by the root.
const PINNED: Totals = Totals {
    states: 488,
    transitions: 1_314,
    depth: 14,
};

const RECONCILER_READ: Action = Action::Record(RecordAction::ReconcilerRead);
const DESIGNATE: Action = Action::Record(RecordAction::Designate(Arm::Pass));
const READ_A: Action = Action::Record(RecordAction::Read(Side::A));
const TAKEOVER_A: Action = Action::Record(RecordAction::TakeOver(Side::A, Arm::Pass));

const SKIPS_TENURE_CHECK: [Action; 6] = [
    RECONCILER_READ,
    DESIGNATE,
    READ_A,
    TAKEOVER_A,
    Action::ReportOne(Side::C),
    Action::Preempt(Side::C),
];

const REPORT_TWO_UNJUDGED: [Action; 10] = [
    RECONCILER_READ,
    DESIGNATE,
    READ_A,
    Action::ReportOne(Side::C),
    Action::Preempt(Side::C),
    TAKEOVER_A,
    Action::ReportOne(Side::A),
    Action::Register(Side::A),
    Action::Preempt(Side::A),
    Action::ReportTwo(Side::C),
];

/// The search over every interleaving, within the fence bound, of the two hosts' steps after an acknowledged
/// takeover, the reconciler's designation of the deposed host and the second takeover holds `NoPreemptOfForeignKey`
/// and `FenceHolds` at every reached state, reaches the four fence decisions and observes the fence witnesses. With
/// the nine decisions the record search reaches, all 13 are reached across the two searches.
#[test]
fn the_fence_search_exhausts_its_bound() {
    let report = search(&Fence::new(Plant::None), CAP);
    println!(
        "tenure-fence-search: {:?} {:?} kinds {} decisions {} witnesses {}",
        report.verdict,
        report.totals,
        report.seen.kinds.len(),
        report.seen.decisions.len(),
        report.seen.witnesses.len()
    );
    assert_eq!(report.verdict, Verdict::Exhaustive);
    assert_eq!(report.totals, PINNED);
    assert_eq!(report.seen.kinds, KINDS.into_iter().collect());
    let reached = DECISIONS.into_iter().chain(RECORD_DECISIONS).collect();
    assert_eq!(report.seen.decisions, reached);
    for witness in WITNESSES {
        assert!(report.seen.witnesses.contains(witness), "{witness}");
    }
    let mut all = report.seen.decisions;
    all.extend(tenure::DECISIONS);
    assert_eq!(all.len(), 13, "{all:?}");
}

/// The record half of the fence root is a state the record world reaches within its own bound: replaying the root's
/// record actions there ends with C owning the root generation at `E = 2` with no standby, the record the fence
/// root holds.
#[test]
fn the_fence_root_record_is_a_state_the_record_world_reaches() {
    let records = Records::new(RecordPlant::None);
    let replayed = replay(&records, &ROOT);
    assert_eq!(replayed.end, End::Applied);
    let reached = *replayed.world.record();
    let fence = Fence::new(Plant::None);
    let root = fence.root();
    assert_eq!(*root.record(), reached);
    assert_eq!(fence.volume().volume, reached.active);
    for side in [Side::A, Side::C] {
        assert_eq!(fence.holder(side).volume, reached.active);
        assert_eq!(fence.holder(side).host, side.host());
    }
    assert_ne!(
        fence.holder(Side::A).instance,
        fence.holder(Side::C).instance
    );
    let before = *records.root().record();
    assert_eq!(
        Target::of(&reached),
        Target {
            generation: before.generation,
            owner: Side::C.host(),
            attempts: 2,
        }
    );
    assert_eq!(reached.standby, None);
}

fn planted(plant: Plant, property: &'static str, path: &[Action]) -> Replay<Fence> {
    let clean = Fence::new(Plant::None);
    let replayed = control(&Fence::new(plant), &clean, CAP, property, path);
    let (_, prefix) = path.split_last().expect("a pinned path is nonempty");
    let before = replay(&clean, prefix);
    assert_eq!(before.end, End::Applied);
    assert_eq!(replayed.world.reservation(), before.world.reservation());
    replayed
}

/// Plant `skips-tenure-check`: the host issues its preempt without the first use of the copied `tenure-check` rule,
/// the one before the preempt; the second use, before admission, stays. The search reports "NoPreemptOfForeignKey"
/// when C preempts A's key after A's second takeover committed, so the store's record names A's tenure at the
/// issuing step. The unplanted replay stops at the model's copy of the `tenure-check` rule, which the ledger entry
/// of that name cites from `Takeover::current`. This is the one plant whose replay stops at a rule of the model in
/// place of a production call.
#[test]
fn a_preempt_without_the_tenure_check_breaks_no_preempt_of_foreign_key() {
    let replayed = planted(
        Plant::SkipsTenureCheck,
        "NoPreemptOfForeignKey",
        &SKIPS_TENURE_CHECK,
    );
    assert_eq!(replayed.last().reply, Reply::Superseded);
    assert_eq!(replayed.last().preempt, None);
    let entry = COPIED.iter().find(|entry| entry.name == "tenure-check");
    let sites = entry.expect("the ledger names the copied rule").sites;
    assert!(
        sites
            .iter()
            .any(|site| site.owner == "Takeover" && site.function == "current")
    );
}

/// Plant `report-two-unjudged`: the host takes the fencing boundary from Report #2 without calling
/// `Fenced::restarted`. The search reports "FenceHolds" when C takes the boundary after A's second takeover
/// preempted C's key, so A's pair holds the reservation. The unplanted replay stops at a `NotSole` refusal from
/// `Fenced::restarted`.
#[test]
fn a_boundary_without_the_report_two_judgment_breaks_fence_holds() {
    let replayed = planted(Plant::ReportTwoUnjudged, "FenceHolds", &REPORT_TWO_UNJUDGED);
    assert_eq!(
        replayed.last().reply,
        Reply::NotSole(NotSole::ForeignHolder)
    );
    assert_eq!(replayed.last().boundary, None);
    let broken = replay(&Fence::new(Plant::ReportTwoUnjudged), &REPORT_TWO_UNJUDGED);
    assert_eq!(
        broken.end,
        End::Violation {
            property: "FenceHolds",
            path: REPORT_TWO_UNJUDGED.to_vec()
        }
    );
    assert_eq!(broken.last().reply, Reply::Superseded);
    let admitted = broken.last().boundary.map(|boundary| boundary.admitted);
    assert_eq!(admitted, Some(false));
}

#[test]
fn a_refusal_outside_the_listed_ones_ends_a_fence_step_as_a_failure() {
    let fence = Fence::new(Plant::None);
    let step = |path: &[Action], action: Action| {
        let reached = replay(&fence, path);
        assert_eq!(reached.end, End::Applied);
        let mut world = reached.world;
        world.vacate();
        fence
            .step(&world, action, &mut Seen::default())
            .err()
            .expect("a refusal the step does not list")
    };
    let first = step(&[], Action::ReportOne(Side::C));
    assert!(
        first.contains("ReportOne(C)") && first.contains("Unresolved"),
        "{first}"
    );
    let second = step(
        &[Action::ReportOne(Side::C), Action::Preempt(Side::C)],
        Action::ReportTwo(Side::C),
    );
    assert!(
        second.contains("ReportTwo(C)") && second.contains("ReservationType"),
        "{second}"
    );
}
