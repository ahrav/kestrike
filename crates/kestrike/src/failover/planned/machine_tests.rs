use std::cell::Cell;
use std::num::NonZeroU32;

use super::*;
use crate::failover::planned::request::{
    Kind, PlannedRequest, RequestKey, Sequence, decode, encode,
};
use crate::failover::records::{Ancestry, Record, Suffix};
use crate::failover::report::ExitOperation;
use crate::net::ownership::ShardGeneration;
use crate::storage::session_at;
use crate::storage::store_tests::record;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Plant {
    TransferBeforeCertify,
    WaitOnBlockers,
    OwnSuffixRequired,
    /// A restart or roll proceeds over a record that names no standby, and the roll's start skips its standby check.
    StandbyIgnored,
}

thread_local! {
    static PLANTED: Cell<Option<Plant>> = const { Cell::new(None) };
    static BLOCKERS: Cell<Option<u32>> = const { Cell::new(None) };
}

pub(crate) fn planted(plant: Plant) -> bool {
    PLANTED.with(Cell::get) == Some(plant)
}

/// The count of outstanding device commands that [`Plant::WaitOnBlockers`] reads while [`drive`] runs.
pub(super) fn blockers() -> Option<u32> {
    BLOCKERS.with(Cell::get)
}

pub(crate) fn with_plant<T>(plant: Plant, f: impl FnOnce() -> T) -> T {
    PLANTED.with(|cell| cell.set(Some(plant)));
    let out = f();
    PLANTED.with(|cell| cell.set(None));
    out
}

const SESSION: u64 = 3 << 32 | 2;
const LATER_SESSION: u64 = 3 << 32 | 4;
const PREDECESSOR: u64 = 2 << 32 | 2;
const DEADLINE: u64 = 1_000;
const END: u64 = 5;

fn session() -> Session {
    session_at(3, 0)
}

fn target() -> Host {
    Host::new(9).unwrap()
}

fn deadline() -> Deadline {
    Deadline::new(DEADLINE).unwrap()
}

fn receipt_checkpoint() -> NamedCheckpoint {
    NamedCheckpoint {
        slot: 1,
        session: SESSION,
        capture: 2,
        units: 2,
    }
}

fn published_checkpoint() -> NamedCheckpoint {
    NamedCheckpoint {
        slot: 2,
        capture: 3,
        ..receipt_checkpoint()
    }
}

fn own_suffix(certified: u64) -> Suffix {
    Suffix {
        session: SESSION,
        start: 0,
        certified,
        end: 64,
    }
}

fn receipt(certified: u64) -> ShardRecord {
    ShardRecord {
        attempts: 1,
        standby: Some(target()),
        checkpoint: Some(receipt_checkpoint()),
        ancestry: Ancestry::new(&[own_suffix(certified)]).unwrap(),
        ..record()
    }
}

fn committed(certified: u64) -> ShardRecord {
    ShardRecord {
        checkpoint: Some(published_checkpoint()),
        ..receipt(certified)
    }
}

fn acknowledged(record: ShardRecord) -> Input {
    Input::Certified(Certified::Acknowledged {
        record,
        floor: Some(0),
    })
}

fn settled(at: u64) -> Input {
    Input::Suffix(Position {
        pending: false,
        durable: at,
        head: at,
    })
}

fn suffix(pending: bool, durable: u64, head: u64) -> Input {
    Input::Suffix(Position {
        pending,
        durable,
        head,
    })
}

fn sealed(request: PlannedRequest) -> AuthenticatedRequest {
    let key = RequestKey::derive(&[0x42; 32]);
    decode(&encode(&request, &key), request.owner, &key).unwrap()
}

fn request(kind: Kind, deadline_us: u32, tenure: &Session) -> AuthenticatedRequest {
    let own = tenure.target();
    sealed(PlannedRequest {
        kind,
        operation: ExitOperation::new([1; 16]).unwrap(),
        sequence: Sequence::of(1_800_000_000, 1),
        shard: tenure.shard(),
        generation: own.generation,
        attempts: own.attempts,
        owner: own.owner,
        deadline_us: NonZeroU32::new(deadline_us).unwrap(),
    })
}

fn started(kind: ExitKind, tenure: &Session, received_us: u64, cap: Deadline) -> Planned {
    let requested = u32::try_from(DEADLINE).unwrap();
    let asked = |kind| {
        let request = request(kind, requested, tenure);
        Planned::requested(&request, tenure, received_us, cap).unwrap()
    };
    match kind {
        ExitKind::Transfer { target } => asked(Kind::Transfer { target }),
        ExitKind::Restart => asked(Kind::Restart),
        ExitKind::Roll { publish } => Planned::roll(publish, tenure, received_us, cap),
    }
}

fn machine(kind: ExitKind) -> Planned {
    started(kind, &session(), 0, deadline())
}

fn transfer() -> ExitKind {
    ExitKind::Transfer { target: target() }
}

const RECORD: usize = 0;
const UNNAMED: usize = 1;
const OTHER: usize = 2;
const PUBLISHED: usize = 3;
const NO_SLOT: usize = 4;
const CERTIFIED: usize = 8;
const SETTLED: usize = 11;
const MOVED: usize = 13;
const CLEAR: usize = 14;
const OPEN: usize = 15;
const TRANSFERRED: usize = 16;
const TRANSFER_REFUSED: usize = 17;
const TRANSFER_UNKNOWN: usize = 18;
const TICK: usize = 19;
const LATE: usize = 20;

fn columns() -> [Input; 22] {
    let unnamed = ShardRecord {
        standby: None,
        ..receipt(0)
    };
    let other = ShardRecord {
        attempts: 2,
        ..receipt(0)
    };
    [
        Input::Record(receipt(0)),
        Input::Record(unnamed),
        Input::Record(other),
        Input::Published(Published::Acknowledged(committed(0))),
        Input::Published(Published::NoSlot),
        Input::Published(Published::Refused),
        Input::Published(Published::Store),
        Input::Published(Published::Acknowledged(receipt(0))),
        acknowledged(committed(END)),
        Input::Certified(Certified::Refused),
        Input::Certified(Certified::Store),
        settled(END),
        suffix(true, END - 1, END),
        settled(END + 1),
        Input::Coverage {
            acknowledgeable: false,
        },
        Input::Coverage {
            acknowledgeable: true,
        },
        Input::Transfer(Transferred::Acknowledged),
        Input::Transfer(Transferred::Refused),
        Input::Transfer(Transferred::Unknown),
        Input::Clock(10),
        Input::Clock(DEADLINE),
        Input::Unopened,
    ]
}

#[test]
fn each_named_column_holds_its_input() {
    let c = columns();
    let named = [
        (RECORD, Input::Record(receipt(0))),
        (
            UNNAMED,
            Input::Record(ShardRecord {
                standby: None,
                ..receipt(0)
            }),
        ),
        (
            OTHER,
            Input::Record(ShardRecord {
                attempts: 2,
                ..receipt(0)
            }),
        ),
        (
            PUBLISHED,
            Input::Published(Published::Acknowledged(committed(0))),
        ),
        (NO_SLOT, Input::Published(Published::NoSlot)),
        (CERTIFIED, acknowledged(committed(END))),
        (SETTLED, settled(END)),
        (MOVED, settled(END + 1)),
        (
            CLEAR,
            Input::Coverage {
                acknowledgeable: false,
            },
        ),
        (
            OPEN,
            Input::Coverage {
                acknowledgeable: true,
            },
        ),
        (TRANSFERRED, Input::Transfer(Transferred::Acknowledged)),
        (TRANSFER_REFUSED, Input::Transfer(Transferred::Refused)),
        (TRANSFER_UNKNOWN, Input::Transfer(Transferred::Unknown)),
        (TICK, Input::Clock(10)),
        (LATE, Input::Clock(DEADLINE)),
    ];
    for (column, input) in named {
        assert_eq!(c[column], input, "column {column}");
    }
}

fn run(planned: &mut Planned, inputs: &[Input]) -> Vec<Step> {
    inputs.iter().map(|input| planned.step(*input)).collect()
}

fn inputs(names: &[usize]) -> Vec<Input> {
    let c = columns();
    names.iter().map(|&column| c[column]).collect()
}

fn to_certifying() -> Vec<Input> {
    inputs(&[RECORD, TICK, PUBLISHED, TICK, CLEAR, SETTLED])
}

fn rows() -> Vec<(&'static str, Planned, &'static str)> {
    let at = |kind: ExitKind, inputs: &[Input]| {
        let mut planned = machine(kind);
        let _ = run(&mut planned, inputs);
        planned
    };
    let certifying = to_certifying();
    let withdrawn = [&certifying[..], &inputs(&[CERTIFIED])].concat();
    let refused = [&withdrawn[..], &inputs(&[TRANSFER_REFUSED])].concat();
    let transferred = [&withdrawn[..], &inputs(&[TRANSFERRED])].concat();
    let exited = [&refused[..], &inputs(&[OTHER])].concat();
    let roll = ExitKind::Roll { publish: false };
    let restart_withdrawn = [
        &inputs(&[RECORD, TICK, NO_SLOT, TICK, CLEAR, SETTLED])[..],
        &[acknowledged(receipt(END))],
    ]
    .concat();
    let restarting = [&restart_withdrawn[..], &inputs(&[TICK])].concat();
    vec![
        ("received", at(transfer(), &[]), "fSOwwwwwwwwwwwwwwwwwDw"),
        (
            "fills stopped",
            at(transfer(), &inputs(&[RECORD])),
            "wSOwwwwwwwwwwwwwwwwcDw",
        ),
        (
            "capturing",
            at(transfer(), &inputs(&[RECORD, TICK])),
            "wSOmCCOCwwwwwwwwwwwwDw",
        ),
        (
            "capturing a restart",
            at(ExitKind::Restart, &inputs(&[RECORD, TICK])),
            "wSOmmCOCwwwwwwwwwwwwDw",
        ),
        (
            "roll without a slot",
            at(roll, &inputs(&[RECORD])),
            "wSOwwwwwwwwwwwwwwwwmDw",
        ),
        (
            "sealed",
            at(transfer(), &certifying[..3]),
            "wSOwwwwwwwwwwwwwwwwsDw",
        ),
        (
            "sealed and closed",
            at(transfer(), &certifying[..5]),
            "wSOwwwwwwwwkwKwwwwwwDw",
        ),
        (
            "certifying",
            at(transfer(), &certifying),
            "wSOwwwwwTCOwwwwwwwwwDw",
        ),
        (
            "certifying a restart",
            at(ExitKind::Restart, &certifying),
            "wSOwwwwwRCOwwwwwwwwwDw",
        ),
        (
            "withdrawn",
            at(transfer(), &withdrawn),
            "wwwwwwwwwwwwwwwwxwwwww",
        ),
        (
            "refused",
            at(transfer(), &refused),
            "rrxwwwwwwwwwwwwwwwwwww",
        ),
        (
            "restart withdrawn",
            at(ExitKind::Restart, &restart_withdrawn),
            "wwwwwwwwwwwwwwwwwwwppw",
        ),
        (
            "transferred",
            at(transfer(), &transferred),
            "wwwwwwwwwwwwwwwwwwwwww",
        ),
        ("exited", at(transfer(), &exited), "wwwwwwwwwwwwwwwwwwwwww"),
        (
            "resumed",
            at(transfer(), &inputs(&[UNNAMED])),
            "wwwwwwwwwwwwwwwwwwwwww",
        ),
        (
            "restarting",
            at(ExitKind::Restart, &restarting),
            "wwwwwwwwwwwwwwwwwwwwww",
        ),
    ]
}

fn declared(code: char, before: State, input: Input) -> (Step, State) {
    let resumed = |reason| (Step::Resume(reason), State::Resumed(reason));
    let restarted = |reason| (Step::Restart(reason), State::Restarting(reason));
    match code {
        'w' => (Step::Wait, before),
        'f' => (Step::StopFills, State::FillsStopped),
        'c' => (Step::Capture, before),
        'm' => (Step::StopMutations, State::Sealed),
        's' => (Step::Seal, before),
        'k' => (Step::Certify { end: END }, before),
        'K' => (Step::Certify { end: END + 1 }, before),
        'T' => (
            Step::Withdraw(Then::Transfer { target: target() }),
            State::Withdrawn,
        ),
        'R' => (Step::Withdraw(Then::Restart), State::Withdrawn),
        'x' if input == Input::Transfer(Transferred::Acknowledged) => {
            (Step::Exit, State::Transferred)
        }
        'x' => (Step::Exit, State::Exited),
        'r' => restarted(Restart::TransferRefused),
        'p' => restarted(Restart::Planned),
        'D' => resumed(Resume::Deadline),
        'C' => resumed(Resume::Cut),
        'S' => resumed(Resume::Standby),
        'O' => resumed(Resume::Store),
        _ => panic!("no code {code}"),
    }
}

#[test]
fn every_state_and_input_pair_takes_its_declared_step() {
    let mut broken = Vec::new();
    for (name, planned, codes) in rows() {
        assert_eq!(codes.len(), columns().len(), "{name}");
        for (column, (input, code)) in columns().into_iter().zip(codes.chars()).enumerate() {
            let mut after = planned.clone();
            let step = after.step(input);
            let expected = declared(code, planned.state(), input);
            if (step, after.state()) != expected {
                broken.push(format!(
                    "{name}, column {column}: {:?} gave {step:?} to {:?}",
                    expected,
                    after.state()
                ));
            }
            let latches = planned.state() == State::Withdrawn && planned.retry.is_none();
            let ignored = match input {
                Input::Record(_) | Input::Published(_) | Input::Certified(_) => true,
                Input::Transfer(_) => !latches,
                Input::Suffix(_) | Input::Coverage { .. } | Input::Clock(_) => false,
                Input::Unopened => false,
            };
            if code == 'w' && ignored && after != planned {
                broken.push(format!(
                    "{name}, column {column}: an ignored input changed the machine"
                ));
            }
        }
    }
    assert_eq!(broken, Vec::<String>::new());
}

#[test]
fn each_failure_before_the_withdrawal_resumes_with_its_reason() {
    let c = columns();
    let certifying = to_certifying();
    let receipt_read = inputs(&[RECORD]);
    let prefixes: [&[Input]; 3] = [&[], &receipt_read, &certifying];
    for prefix in prefixes {
        let failures = [
            (c[LATE], Resume::Deadline),
            (c[OTHER], Resume::Store),
            (c[UNNAMED], Resume::Standby),
            (Input::Certified(Certified::Store), Resume::Store),
        ];
        for (input, reason) in failures {
            let mut planned = machine(transfer());
            let mut steps = run(&mut planned, prefix);
            let before = planned.state();
            steps.push(planned.step(input));
            let last = *steps.last().unwrap();
            if before == State::Sealed || !matches!(input, Input::Certified(_)) {
                assert_eq!(last, Step::Resume(reason), "{before:?} {input:?}");
                assert_eq!(planned.state(), State::Resumed(reason));
            }
            assert!(
                !steps
                    .iter()
                    .any(|step| matches!(step, Step::Restart(_) | Step::Withdraw(_))),
                "{steps:?}"
            );
        }
    }
    let mut cut = machine(transfer());
    let _ = run(&mut cut, &receipt_read);
    assert_eq!(cut.step(c[TICK]), Step::Capture);
    assert_eq!(
        cut.step(Input::Published(Published::Refused)),
        Step::Resume(Resume::Cut)
    );
}

#[test]
fn no_input_resumes_a_withdrawn_exit() {
    for (name, planned, _) in rows() {
        if planned.state() != State::Withdrawn {
            continue;
        }
        for input in columns() {
            let mut after = planned.clone();
            let step = after.step(input);
            assert!(!matches!(step, Step::Resume(_)), "{name}: {input:?}");
            assert!(
                matches!(
                    after.state(),
                    State::Withdrawn | State::Transferred | State::Exited | State::Restarting(_)
                ),
                "{name}: {input:?}"
            );
        }
    }
}

fn withdrawal_follows_the_cut(kind: ExitKind, trace: &[(Input, Step)]) -> bool {
    let (mut receipt, mut published, mut skipped) = (None, None, false);
    let mut certify = None;
    let (mut durable, mut head) = (0, 0);
    for (input, step) in trace {
        if let (Input::Record(record), Step::StopFills) = (input, step) {
            receipt = record.checkpoint;
        }
        if let Input::Suffix(position) = input {
            durable = durable.max(position.durable);
            head = head.max(position.head);
        }
        if *step == Step::StopMutations {
            match input {
                Input::Published(Published::Acknowledged(record)) => published = record.checkpoint,
                _ => skipped = true,
            }
        }
        if let Step::Certify { end } = step {
            certify = Some(*end);
        }
        if let Step::Withdraw(_) = step {
            let Input::Certified(Certified::Acknowledged { record, .. }) = input else {
                return false;
            };
            let named = match published {
                Some(published) => record.checkpoint == Some(published),
                None => {
                    skipped
                        && !matches!(kind, ExitKind::Transfer { .. })
                        && record.checkpoint.is_some()
                        && record.checkpoint == receipt
                }
            };
            let own = (record.ancestry.as_slice().iter()).find(|suffix| suffix.session == SESSION);
            let recorded = own.map_or(record.cut, |own| own.certified);
            return named && certify == Some(durable) && durable == head && recorded == durable;
        }
    }
    true
}

fn kinds() -> [ExitKind; 4] {
    [
        transfer(),
        ExitKind::Restart,
        ExitKind::Roll { publish: true },
        ExitKind::Roll { publish: false },
    ]
}

fn cut_record(kind: ExitKind, certified: u64) -> ShardRecord {
    match kind {
        ExitKind::Roll { publish: false } => receipt(certified),
        ExitKind::Transfer { .. } | ExitKind::Restart | ExitKind::Roll { publish: true } => {
            committed(certified)
        }
    }
}

fn to_sealed(kind: ExitKind) -> Vec<Input> {
    match kind {
        ExitKind::Roll { publish: false } => inputs(&[RECORD, TICK, TICK, CLEAR]),
        ExitKind::Transfer { .. } | ExitKind::Restart | ExitKind::Roll { publish: true } => {
            inputs(&[RECORD, TICK, PUBLISHED, TICK, CLEAR])
        }
    }
}

fn progress(kind: ExitKind) -> Vec<Input> {
    let certify = acknowledged(cut_record(kind, END));
    [&to_sealed(kind)[..], &[settled(END), certify]].concat()
}

fn moved_progress(kind: ExitKind) -> Vec<Input> {
    let first = acknowledged(cut_record(kind, END));
    let second = acknowledged(cut_record(kind, END + 1));
    let moves = [settled(END), settled(END + 1), first, second];
    [&to_sealed(kind)[..], &moves].concat()
}

fn recertified(trace: &[(Input, Step)]) -> bool {
    let steps: Vec<Step> = trace
        .iter()
        .map(|(_, step)| *step)
        .filter(|step| matches!(step, Step::Certify { .. } | Step::Withdraw(_)))
        .collect();
    steps.windows(3).any(|window| {
        window[..2] == [Step::Certify { end: END }, Step::Certify { end: END + 1 }]
            && matches!(window[2], Step::Withdraw(_))
    })
}

fn walks(kind: ExitKind) -> (Vec<Vec<(Input, Step)>>, u32, u32) {
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let drawn: Vec<Input> = (columns().into_iter())
        .filter(|input| !matches!(input, Input::Clock(DEADLINE) | Input::Unopened))
        .collect();
    let scripts = [progress(kind), moved_progress(kind)];
    let template = machine(kind);
    let (mut broken, mut withdrew, mut again) = (Vec::new(), 0, 0);
    for walk in 0..5_000 {
        let script = &scripts[walk % 2];
        let mut planned = template.clone();
        let mut trace = Vec::with_capacity(32);
        let mut at = 0;
        for _ in 0..32 {
            let input = match next() % 2 {
                0 if at < script.len() => {
                    at += 1;
                    script[at - 1]
                }
                _ => drawn[(next() % drawn.len() as u64) as usize],
            };
            trace.push((input, planned.step(input)));
        }
        let reached = trace
            .iter()
            .any(|(_, step)| matches!(step, Step::Withdraw(_)));
        withdrew += u32::from(reached);
        again += u32::from(reached && recertified(&trace));
        if !withdrawal_follows_the_cut(kind, &trace) {
            broken.push(trace);
        }
    }
    (broken, withdrew, again)
}

#[test]
fn every_withdrawal_follows_the_publish_and_a_certify_at_the_head() {
    for kind in kinds() {
        let (broken, withdrew, again) = walks(kind);
        assert!(withdrew >= 1_000, "{kind:?}: {withdrew} walks withdrew");
        assert!(
            again >= 100,
            "{kind:?}: {again} walks withdrew after a second certify"
        );
        assert_eq!(broken.len(), 0, "{kind:?}: {:?}", broken.first());
    }
}

#[test]
fn control_transfer_before_certify_fails_the_cut_rule() {
    for kind in kinds() {
        let (broken, _, _) = with_plant(Plant::TransferBeforeCertify, || walks(kind));
        assert!(
            !broken.is_empty(),
            "HandoffCutIsExact: the planted transfer passed for {kind:?}"
        );
    }
}

fn classify(input: &Input) {
    match input {
        Input::Record(_)
        | Input::Published(_)
        | Input::Certified(_)
        | Input::Suffix(_)
        | Input::Coverage { acknowledgeable: _ }
        | Input::Transfer(_)
        | Input::Clock(_)
        | Input::Unopened => {}
    }
}

/// Runs a transfer through `turns` turns of a driver that performs each step and feeds every completion, with
/// `blockers` device commands outstanding throughout, and returns the withdrawal if one comes.
fn drive(blockers: Option<u32>, turns: u64) -> Option<Step> {
    BLOCKERS.with(|cell| cell.set(blockers));
    let c = columns();
    let mut planned = machine(transfer());
    let mut completions = vec![c[RECORD]];
    let mut withdrawal = None;
    'turns: for turn in 1..=turns {
        let mut fed = vec![Input::Clock(turn), c[CLEAR], c[SETTLED]];
        fed.append(&mut completions);
        for input in fed {
            classify(&input);
            match planned.step(input) {
                Step::Capture => completions.push(c[PUBLISHED]),
                Step::Certify { end } => completions.push(acknowledged(committed(end))),
                step @ Step::Withdraw(_) => {
                    withdrawal = Some(step);
                    break 'turns;
                }
                _ => {}
            }
        }
    }
    BLOCKERS.with(|cell| cell.set(None));
    withdrawal
}

#[test]
fn an_unrelated_device_read_leaves_the_transfer_reachable() {
    let transfer = Some(Step::Withdraw(Then::Transfer { target: target() }));
    assert_eq!(drive(Some(1), 100), transfer);
    let idle = with_plant(Plant::WaitOnBlockers, || drive(None, 100));
    assert_eq!(idle, transfer, "the planted wait needs a blocker");
}

/// The planted machine holds the certify's acknowledgment while a device command is outstanding.
#[test]
fn control_a_wait_on_blockers_never_reaches_the_transfer() {
    let held = with_plant(Plant::WaitOnBlockers, || drive(Some(1), DEADLINE - 1));
    assert_eq!(
        held, None,
        "#120 R11: the planted wait reached the transfer"
    );
}

#[test]
fn the_deadline_bound_refuses_zero_and_caps_a_longer_request() {
    assert_eq!(Deadline::new(0), Err(DeadlineError::Zero));
    let cap = Deadline::new(500).unwrap();
    assert_eq!(cap.of(NonZeroU32::new(900)), 500);
    assert_eq!(cap.of(NonZeroU32::new(200)), 200);
    assert_eq!(cap.of(None), 500, "a roll takes the cap");
    let mut late = machine(transfer());
    let _ = run(&mut late, &inputs(&[RECORD]));
    assert_eq!(
        late.step(Input::Clock(DEADLINE + 1)),
        Step::Resume(Resume::Deadline)
    );
    let received = 2_000;
    let tenure = session();
    let shorter = request(Kind::Transfer { target: target() }, 200, &tenure);
    let longer = request(Kind::Transfer { target: target() }, 900, &tenure);
    let requested = |request| Planned::requested(request, &tenure, received, cap).unwrap();
    let machines = [
        (requested(&shorter), 200),
        (requested(&longer), 500),
        (Planned::roll(true, &tenure, received, cap), 500),
    ];
    for (mut planned, expires) in machines {
        let _ = run(&mut planned, &inputs(&[RECORD]));
        assert_eq!(
            planned.step(Input::Clock(received + expires - 1)),
            Step::Capture,
            "live until {expires}"
        );
        assert_eq!(
            planned.step(Input::Clock(received + expires)),
            Step::Resume(Resume::Deadline)
        );
    }
}

#[test]
fn a_request_naming_another_tenure_starts_no_exit() {
    let tenure = session();
    let own = request(Kind::Restart, 200, &tenure);
    assert!(Planned::requested(&own, &tenure, 0, deadline()).is_ok());
    let named = *own.request();
    let others = [
        (
            "shard",
            PlannedRequest {
                shard: Shard::new(named.shard.get() + 1).unwrap(),
                ..named
            },
        ),
        (
            "generation",
            PlannedRequest {
                generation: ShardGeneration::new(named.generation.get() + 1).unwrap(),
                ..named
            },
        ),
        (
            "owner",
            PlannedRequest {
                owner: Host::new(named.owner.get() + 1).unwrap(),
                ..named
            },
        ),
        (
            "an earlier E",
            PlannedRequest {
                attempts: named.attempts - 1,
                ..named
            },
        ),
        (
            "a later E",
            PlannedRequest {
                attempts: named.attempts + 1,
                ..named
            },
        ),
    ];
    for (field, other) in others {
        assert_eq!(
            Planned::requested(&sealed(other), &tenure, 0, deadline()),
            Err(StartError::Tenure),
            "{field}"
        );
    }
    assert_eq!(
        Planned::requested(&own, &successor(), 0, deadline()),
        Err(StartError::Tenure),
        "the host's next tenure"
    );
}

#[test]
fn each_precondition_false_alone_resumes_with_its_reason() {
    let good = committed(END);
    let floorless = Input::Certified(Certified::Acknowledged {
        record: good,
        floor: None,
    });
    let with = |change: &dyn Fn(&mut ShardRecord)| {
        let mut record = good;
        change(&mut record);
        acknowledged(record)
    };
    let chain = |suffixes: &[Suffix]| {
        with(&|record| {
            record.ancestry = Ancestry::new(suffixes).unwrap();
        })
    };
    let predecessor = |certified| Suffix {
        session: PREDECESSOR,
        start: 0,
        certified,
        end: END,
    };
    let current = |certified| Suffix {
        session: SESSION,
        start: END,
        certified,
        end: 64,
    };
    let receipt_named = with(&|record| record.checkpoint = Some(receipt_checkpoint()));
    let other_checkpoint = with(&|record| {
        record.checkpoint = Some(NamedCheckpoint {
            capture: 4,
            ..published_checkpoint()
        });
    });
    let other_cut = with(&|record| record.cut = 1);
    let other_standby = with(&|record| record.standby = Some(Host::new(8).unwrap()));
    let c = columns();
    let cases: [(&str, Vec<Input>, Resume); 10] = [
        ("W1 floor", vec![floorless], Resume::Cut),
        ("W2 receipt checkpoint", vec![receipt_named], Resume::Cut),
        ("W2 other checkpoint", vec![other_checkpoint], Resume::Cut),
        ("W2 other cut", vec![other_cut], Resume::Cut),
        (
            "W3 certified end",
            vec![acknowledged(committed(END - 1))],
            Resume::Cut,
        ),
        (
            "W3 predecessor certified at the end",
            vec![chain(&[predecessor(END), current(END + 1)])],
            Resume::Cut,
        ),
        (
            "W3 no own suffix",
            vec![chain(&[predecessor(END)])],
            Resume::Cut,
        ),
        (
            "W4 coverage",
            vec![c[OPEN], acknowledged(good)],
            Resume::Cut,
        ),
        ("W5 standby", vec![other_standby], Resume::Standby),
        (
            "W6 deadline",
            vec![c[LATE], acknowledged(good)],
            Resume::Deadline,
        ),
    ];
    for (name, inputs, reason) in cases {
        let mut planned = machine(transfer());
        let _ = run(&mut planned, &to_certifying());
        let steps = run(&mut planned, &inputs);
        assert!(steps.contains(&Step::Resume(reason)), "{name}: {steps:?}");
        let withdrew = steps.iter().any(|step| matches!(step, Step::Withdraw(_)));
        assert!(!withdrew, "{name}");
        assert_eq!(planned.state(), State::Resumed(reason), "{name}");
    }
    let mut passing = machine(transfer());
    let _ = run(&mut passing, &to_certifying());
    assert!(matches!(
        passing.step(acknowledged(good)),
        Step::Withdraw(_)
    ));
}

#[test]
fn each_cut_check_false_alone_resumes_a_restart_or_roll() {
    let kinds = [
        ExitKind::Restart,
        ExitKind::Roll { publish: true },
        ExitKind::Roll { publish: false },
    ];
    for kind in kinds {
        let good = cut_record(kind, END);
        let floorless = Input::Certified(Certified::Acknowledged {
            record: good,
            floor: None,
        });
        let other_checkpoint = acknowledged(ShardRecord {
            checkpoint: Some(NamedCheckpoint {
                capture: 4,
                ..published_checkpoint()
            }),
            ..good
        });
        let mut cases = vec![
            ("W1 floor", floorless),
            ("W2 checkpoint", other_checkpoint),
            ("W3 certified end", acknowledged(cut_record(kind, END - 1))),
        ];
        if kind != (ExitKind::Roll { publish: false }) {
            cases.push(("W2 receipt checkpoint", acknowledged(receipt(END))));
        }
        let sealed = [&to_sealed(kind)[..], &[settled(END)]].concat();
        for (name, certify) in cases {
            let mut planned = machine(kind);
            let steps = run(&mut planned, &sealed);
            assert_eq!(steps.last(), Some(&Step::Certify { end: END }), "{kind:?}");
            assert_eq!(
                planned.step(certify),
                Step::Resume(Resume::Cut),
                "{kind:?} {name}"
            );
        }
        let open = [&to_sealed(kind)[..], &inputs(&[OPEN]), &[settled(END)]].concat();
        let mut coverage = machine(kind);
        let _ = run(&mut coverage, &open);
        assert_eq!(
            coverage.step(acknowledged(good)),
            Step::Resume(Resume::Cut),
            "{kind:?} W4"
        );
        let mut passing = machine(kind);
        let _ = run(&mut passing, &sealed);
        assert_eq!(
            passing.step(acknowledged(good)),
            Step::Withdraw(Then::Restart)
        );
    }
}

#[test]
fn the_own_session_suffix_decides_w3_among_several() {
    let tenure = session_at(3, 1);
    assert_eq!(tenure.get(), LATER_SESSION);
    let at = |certified| {
        let earlier = Suffix {
            session: SESSION,
            start: 0,
            certified: 1,
            end: 2,
        };
        let own = Suffix {
            session: LATER_SESSION,
            start: 2,
            certified,
            end: 64,
        };
        ShardRecord {
            attempts: 2,
            ancestry: Ancestry::new(&[earlier, own]).unwrap(),
            ..receipt(0)
        }
    };
    assert_eq!(ShardRecord::decode(&at(2).encode()), Ok(at(2)));
    assert_eq!(at(END).succeeds(&at(2)), Ok(()));
    for (certified, expected) in [
        (END, Step::Withdraw(Then::Restart)),
        (END - 1, Step::Resume(Resume::Cut)),
    ] {
        let mut planned = Planned::roll(false, &tenure, 0, deadline());
        let script = [
            &[Input::Record(at(2))][..],
            &inputs(&[TICK, TICK, CLEAR, SETTLED]),
        ]
        .concat();
        let steps = run(&mut planned, &script);
        assert_eq!(steps.last(), Some(&Step::Certify { end: END }));
        assert_eq!(planned.step(acknowledged(at(certified))), expected);
    }
}

#[test]
fn a_coverage_reading_before_the_stop_of_mutations_clears_nothing() {
    let no_reading = inputs(&[RECORD, TICK, PUBLISHED, TICK, SETTLED]);
    let before_stop = inputs(&[RECORD, CLEAR, TICK, PUBLISHED, TICK, SETTLED]);
    for prefix in [no_reading, before_stop] {
        let mut planned = machine(transfer());
        let steps = run(&mut planned, &prefix);
        assert_eq!(steps.last(), Some(&Step::Certify { end: END }), "{steps:?}");
        assert_eq!(
            planned.step(acknowledged(committed(END))),
            Step::Resume(Resume::Cut)
        );
    }
}

#[test]
fn a_drain_without_a_publish_needs_the_receipts_checkpoint() {
    let unnamed = ShardRecord {
        checkpoint: None,
        ..receipt(END)
    };
    let entries = [
        (
            ExitKind::Roll { publish: false },
            inputs(&[RECORD, TICK, TICK, CLEAR, SETTLED]),
        ),
        (
            ExitKind::Restart,
            inputs(&[RECORD, TICK, NO_SLOT, TICK, CLEAR, SETTLED]),
        ),
    ];
    for (kind, prefix) in entries {
        let mut planned = machine(kind);
        let steps = run(&mut planned, &prefix);
        assert_eq!(steps.last(), Some(&Step::Certify { end: END }), "{kind:?}");
        for record in [unnamed, committed(END)] {
            assert_eq!(
                planned.clone().step(acknowledged(record)),
                Step::Resume(Resume::Cut),
                "{kind:?}"
            );
        }
        assert_eq!(
            planned.step(acknowledged(receipt(END))),
            Step::Withdraw(Then::Restart)
        );
    }
}

#[test]
fn a_checkpoint_covering_the_whole_log_withdraws_with_no_own_suffix() {
    let short = ShardRecord {
        ancestry: Ancestry::new(&[Suffix {
            end: END,
            ..own_suffix(0)
        }])
        .unwrap(),
        ..receipt(0)
    };
    let whole = ShardRecord {
        cut: END,
        ancestry: Ancestry::default(),
        ..committed(0)
    };
    assert_eq!(whole.succeeds(&short), Ok(()));
    for (head, expected) in [
        (END, Step::Withdraw(Then::Transfer { target: target() })),
        (END + 1, Step::Resume(Resume::Cut)),
    ] {
        let mut planned = machine(transfer());
        let script = [
            Input::Record(short),
            Input::Clock(10),
            Input::Published(Published::Acknowledged(whole)),
            Input::Clock(10),
            Input::Coverage {
                acknowledgeable: false,
            },
            settled(head),
        ];
        let steps = run(&mut planned, &script);
        assert_eq!(steps.last(), Some(&Step::Certify { end: head }));
        assert_eq!(planned.step(acknowledged(whole)), expected);
    }
    let previous = ShardRecord {
        cut: END,
        ancestry: Ancestry::default(),
        ..receipt(0)
    };
    assert_eq!(ShardRecord::decode(&previous.encode()), Ok(previous));
    for (head, expected) in [
        (END, Step::Withdraw(Then::Restart)),
        (END + 1, Step::Resume(Resume::Cut)),
    ] {
        let mut roll = machine(ExitKind::Roll { publish: false });
        let script = [
            &[Input::Record(previous)][..],
            &inputs(&[TICK, TICK, CLEAR]),
            &[settled(head)],
        ]
        .concat();
        let _ = run(&mut roll, &script);
        assert_eq!(roll.step(acknowledged(previous)), expected);
    }
}

#[test]
fn a_block_after_the_certified_end_certifies_again() {
    let c = columns();
    let mut moved = machine(transfer());
    let _ = run(&mut moved, &to_certifying());
    assert_eq!(moved.step(c[MOVED]), Step::Wait);
    assert_eq!(
        moved.step(acknowledged(committed(END))),
        Step::Certify { end: END + 1 },
        "a settled position past the end certifies at once"
    );
    assert!(matches!(
        moved.step(acknowledged(committed(END + 1))),
        Step::Withdraw(_)
    ));
    let mut pending = machine(transfer());
    let _ = run(&mut pending, &to_certifying());
    assert_eq!(pending.step(suffix(true, END, END)), Step::Wait);
    assert_eq!(pending.step(acknowledged(committed(END))), Step::Wait);
    assert_eq!(pending.step(c[MOVED]), Step::Certify { end: END + 1 });
    assert!(matches!(
        pending.step(acknowledged(committed(END + 1))),
        Step::Withdraw(_)
    ));
}

#[test]
fn a_snapshot_behind_the_newest_one_is_kept_out() {
    let c = columns();
    let cases = [
        (
            "lower durable",
            vec![c[MOVED], settled(END)],
            Step::Certify { end: END + 1 },
        ),
        (
            "lower head",
            vec![suffix(true, END, END + 1), settled(END)],
            Step::Wait,
        ),
        (
            "lower durable at the head",
            vec![suffix(false, END - 1, END)],
            Step::Withdraw(Then::Transfer { target: target() }),
        ),
        (
            "settled after pending",
            vec![suffix(true, END, END), settled(END)],
            Step::Wait,
        ),
    ];
    for (name, snapshots, expected) in cases {
        let mut planned = machine(transfer());
        let _ = run(&mut planned, &to_certifying());
        let steps = run(&mut planned, &snapshots);
        assert!(steps.iter().all(|step| *step == Step::Wait), "{name}");
        assert_eq!(
            planned.step(acknowledged(committed(END))),
            expected,
            "{name}"
        );
        assert_ne!(planned.state(), State::Resumed(Resume::Cut), "{name}");
    }
}

#[test]
fn a_position_behind_its_head_waits_to_certify() {
    let mut planned = machine(transfer());
    let _ = run(&mut planned, &to_certifying()[..5]);
    assert_eq!(planned.step(suffix(false, END - 1, END)), Step::Wait);
    assert_eq!(planned.step(settled(END)), Step::Certify { end: END });
}

#[test]
fn publish_and_certify_acknowledgments_check_their_record() {
    let c = columns();
    let capture = |record: ShardRecord| {
        let mut planned = machine(transfer());
        let _ = run(&mut planned, &inputs(&[RECORD, TICK]));
        planned.step(Input::Published(Published::Acknowledged(record)))
    };
    let foreign = NamedCheckpoint {
        session: PREDECESSOR,
        ..published_checkpoint()
    };
    let publishes = [
        (
            ShardRecord {
                checkpoint: None,
                ..committed(0)
            },
            Resume::Cut,
        ),
        (receipt(0), Resume::Cut),
        (
            ShardRecord {
                checkpoint: Some(foreign),
                ..committed(0)
            },
            Resume::Cut,
        ),
        (
            ShardRecord {
                attempts: 2,
                ..committed(0)
            },
            Resume::Store,
        ),
        (
            ShardRecord {
                standby: None,
                ..committed(0)
            },
            Resume::Standby,
        ),
    ];
    for (record, reason) in publishes {
        assert_eq!(capture(record), Step::Resume(reason), "{record:?}");
    }
    assert_eq!(capture(committed(0)), Step::StopMutations);
    let replaced = ShardRecord {
        standby: Some(Host::new(8).unwrap()),
        ..committed(END)
    };
    let foreign_tenure = ShardRecord {
        attempts: 2,
        ..committed(END)
    };
    let certifies = [
        (vec![], foreign_tenure, Resume::Store),
        (vec![c[MOVED]], replaced, Resume::Standby),
        (vec![c[OPEN]], replaced, Resume::Standby),
    ];
    for (before, record, reason) in certifies {
        let mut planned = machine(transfer());
        let _ = run(&mut planned, &[&to_certifying()[..], &before].concat());
        assert_eq!(planned.step(acknowledged(record)), Step::Resume(reason));
        assert_eq!(planned.state(), State::Resumed(reason));
    }
}

#[test]
fn a_record_of_another_tenure_resumes_or_decides_by_its_tenure() {
    let own = receipt(0);
    let variants = [
        (
            ShardRecord {
                shard: Shard::new(own.shard.get() + 1).unwrap(),
                ..own
            },
            Step::Wait,
        ),
        (
            ShardRecord {
                generation: ShardGeneration::new(4).unwrap(),
                ..own
            },
            Step::Exit,
        ),
        (
            ShardRecord {
                generation: ShardGeneration::new(4).unwrap(),
                attempts: 0,
                standby: None,
                ..own
            },
            Step::Exit,
        ),
        (
            ShardRecord {
                generation: ShardGeneration::new(2).unwrap(),
                ..own
            },
            Step::Wait,
        ),
        (
            ShardRecord {
                generation: ShardGeneration::new(2).unwrap(),
                attempts: 5,
                ..own
            },
            Step::Wait,
        ),
        (
            ShardRecord {
                owner: target(),
                ..own
            },
            Step::Wait,
        ),
        (ShardRecord { attempts: 2, ..own }, Step::Exit),
    ];
    for (outcome, reason) in [
        (TRANSFER_REFUSED, Restart::TransferRefused),
        (TRANSFER_UNKNOWN, Restart::TransferUnknown),
    ] {
        let mut failed = machine(transfer());
        let _ = run(
            &mut failed,
            &[&to_certifying()[..], &inputs(&[CERTIFIED, outcome])].concat(),
        );
        assert_eq!(failed.state(), State::Withdrawn);
        for (record, after_failure) in variants {
            let mut fresh = machine(transfer());
            assert_eq!(
                fresh.step(Input::Record(record)),
                Step::Resume(Resume::Store)
            );
            let mut withdrawn = failed.clone();
            assert_eq!(
                withdrawn.step(Input::Record(record)),
                after_failure,
                "{record:?}"
            );
            if after_failure == Step::Wait {
                assert_eq!(withdrawn.state(), State::Withdrawn);
                assert_eq!(withdrawn.step(Input::Record(own)), Step::Restart(reason));
            } else {
                assert_eq!(withdrawn.state(), State::Exited);
            }
        }
    }
}

#[test]
fn a_transfer_outcome_ends_in_one_exit_or_one_restart() {
    let c = columns();
    let mut withdrawn = machine(transfer());
    let _ = run(&mut withdrawn, &to_certifying());
    assert!(matches!(withdrawn.step(c[CERTIFIED]), Step::Withdraw(_)));
    let mut acknowledged = withdrawn.clone();
    assert_eq!(acknowledged.step(c[TRANSFERRED]), Step::Exit);
    assert_eq!(acknowledged.state(), State::Transferred);
    let target_named = ShardRecord {
        owner: target(),
        attempts: 2,
        standby: None,
        ..committed(END)
    };
    for (outcome, later, reason) in [
        (TRANSFER_REFUSED, TRANSFER_UNKNOWN, Restart::TransferRefused),
        (TRANSFER_UNKNOWN, TRANSFER_REFUSED, Restart::TransferUnknown),
    ] {
        let mut other = withdrawn.clone();
        assert_eq!(other.step(c[outcome]), Step::Wait);
        for late in [c[TRANSFERRED], c[later]] {
            assert_eq!(other.step(late), Step::Wait, "one outcome");
        }
        let mut own = other.clone();
        assert_eq!(other.step(Input::Record(target_named)), Step::Exit);
        assert_eq!(other.state(), State::Exited);
        assert_eq!(own.step(c[RECORD]), Step::Restart(reason));
        assert_eq!(own.step(c[RECORD]), Step::Wait, "one restart");
    }
}

#[test]
fn the_attempt_budget_bounds_each_exit() {
    let cases = [
        (transfer(), ATTEMPTS_MAX - 2, true),
        (transfer(), ATTEMPTS_MAX - 1, false),
        (ExitKind::Restart, ATTEMPTS_MAX - 1, true),
        (ExitKind::Restart, ATTEMPTS_MAX, false),
        (ExitKind::Roll { publish: true }, ATTEMPTS_MAX - 1, true),
        (ExitKind::Roll { publish: false }, ATTEMPTS_MAX, false),
    ];
    for (kind, attempts, admitted) in cases {
        let tenure = session_at(3, attempts - 1);
        assert_eq!(tenure.target().attempts, attempts);
        let mut planned = started(kind, &tenure, 0, deadline());
        let step = planned.step(Input::Record(ShardRecord {
            attempts,
            ..receipt(0)
        }));
        let expected = match admitted {
            true => Step::StopFills,
            false => Step::Resume(Resume::Store),
        };
        assert_eq!(step, expected, "{kind:?} at E = {attempts}");
    }
}

#[test]
fn a_roll_or_restart_runs_its_steps_in_order_and_restarts_once() {
    let restart_steps = |publish: bool| {
        let mut steps = vec![Step::StopFills];
        if publish {
            steps.push(Step::Capture);
        }
        steps.extend([
            Step::StopMutations,
            Step::Seal,
            Step::Certify { end: END },
            Step::Withdraw(Then::Restart),
            Step::Restart(Restart::Planned),
        ]);
        steps
    };
    let previous = [acknowledged(receipt(END))];
    let no_slot = [
        &inputs(&[RECORD, TICK, NO_SLOT, TICK, CLEAR, SETTLED])[..],
        &previous,
    ]
    .concat();
    let traces = [
        (ExitKind::Restart, progress(ExitKind::Restart), true),
        (
            ExitKind::Roll { publish: true },
            progress(ExitKind::Roll { publish: true }),
            true,
        ),
        (
            ExitKind::Roll { publish: false },
            progress(ExitKind::Roll { publish: false }),
            false,
        ),
        (ExitKind::Roll { publish: true }, no_slot, true),
    ];
    let c = columns();
    for (kind, script, publish) in traces {
        let mut planned = machine(kind);
        let mut steps = run(&mut planned, &[&script[..], &[c[TICK], c[TICK]]].concat());
        assert_eq!(steps.pop(), Some(Step::Wait), "{kind:?}: one restart");
        steps.retain(|step| *step != Step::Wait);
        assert_eq!(steps, restart_steps(publish), "{kind:?}");
    }
    for kind in [
        ExitKind::Restart,
        ExitKind::Roll { publish: true },
        ExitKind::Roll { publish: false },
    ] {
        let mut script = progress(kind);
        let Some(Input::Certified(Certified::Acknowledged { record, floor })) = script.pop() else {
            panic!("the progress ends in the certify");
        };
        let lost = Input::Certified(Certified::Acknowledged {
            record: ShardRecord {
                standby: None,
                ..record
            },
            floor,
        });
        let mut planned = machine(kind);
        let steps = run(&mut planned, &[&script[..], &[lost]].concat());
        assert_eq!(
            steps.last(),
            Some(&Step::Resume(Resume::Standby)),
            "{kind:?}"
        );
        assert!(!steps.iter().any(|step| matches!(step, Step::Withdraw(_))));
    }
    let mut unnamed = machine(ExitKind::Roll { publish: true });
    assert_eq!(unnamed.step(c[UNNAMED]), Step::Resume(Resume::Standby));
    let mut transfer = machine(transfer());
    let _ = run(&mut transfer, &inputs(&[RECORD, TICK]));
    assert_eq!(
        transfer.step(c[NO_SLOT]),
        Step::Resume(Resume::Cut),
        "a transfer with no free slot resumes"
    );
}

#[test]
fn the_status_follows_the_state() {
    let statuses = [
        ("received", ExitStatus::Received),
        ("fills stopped", ExitStatus::Draining),
        ("capturing", ExitStatus::Draining),
        ("capturing a restart", ExitStatus::Draining),
        ("roll without a slot", ExitStatus::Draining),
        ("sealed", ExitStatus::Draining),
        ("sealed and closed", ExitStatus::Draining),
        ("certifying", ExitStatus::Draining),
        ("certifying a restart", ExitStatus::Draining),
        ("withdrawn", ExitStatus::Withdrawn),
        ("refused", ExitStatus::Withdrawn),
        ("restart withdrawn", ExitStatus::Withdrawn),
        ("transferred", ExitStatus::Exited),
        ("exited", ExitStatus::Exited),
        ("resumed", ExitStatus::Resumed(Resume::Standby)),
        ("restarting", ExitStatus::Restarting(Restart::Planned)),
    ];
    let rows = rows();
    assert_eq!(rows.len(), statuses.len());
    for ((name, planned, _), (expected_name, status)) in rows.into_iter().zip(statuses) {
        assert_eq!(name, expected_name);
        assert_eq!(planned.status(), status, "{name}");
    }
    let c = columns();
    let mut refused = machine(transfer());
    let _ = run(
        &mut refused,
        &[
            &to_certifying()[..],
            &inputs(&[CERTIFIED, TRANSFER_REFUSED, RECORD]),
        ]
        .concat(),
    );
    assert_eq!(
        refused.status(),
        ExitStatus::Restarting(Restart::TransferRefused)
    );
    let mut cut = machine(transfer());
    let _ = run(
        &mut cut,
        &[&to_certifying()[..], &[c[OPEN], c[CERTIFIED]]].concat(),
    );
    assert_eq!(cut.status(), ExitStatus::Resumed(Resume::Cut));
    let request = Kind::Transfer { target: target() };
    assert_eq!(ExitKind::from(request), transfer());
    assert_eq!(ExitKind::from(Kind::Restart), ExitKind::Restart);
    assert_eq!(machine(ExitKind::Restart).kind(), ExitKind::Restart);
    assert_eq!(machine(transfer()).kind(), transfer());
}

#[test]
fn the_fixtures_are_records_the_store_accepts() {
    let tenure = session();
    assert_eq!(tenure.get(), SESSION);
    assert_eq!(tenure.target(), Target::of(&receipt(0)));
    assert_eq!(tenure.shard(), receipt(0).shard);
    for fixture in [receipt(0), committed(0), committed(END), receipt(END)] {
        assert_eq!(ShardRecord::decode(&fixture.encode()), Ok(fixture));
    }
    assert_eq!(committed(0).succeeds(&receipt(0)), Ok(()));
    assert_eq!(committed(END).succeeds(&committed(0)), Ok(()));
    assert_eq!(committed(END + 1).succeeds(&committed(END)), Ok(()));
    assert_eq!(receipt(END).succeeds(&receipt(0)), Ok(()));
    assert_eq!(receipt(END + 1).succeeds(&receipt(END)), Ok(()));
    let later = successor();
    assert_eq!(later.get(), LATER_SESSION);
    assert_eq!(later.target(), Target::of(&predecessor_only()));
    assert_eq!(later.shard(), predecessor_only().shard);
    for fixture in [predecessor_only(), opened()] {
        assert_eq!(ShardRecord::decode(&fixture.encode()), Ok(fixture));
    }
    assert_eq!(predecessor_only().succeeds(&predecessor_only()), Ok(()));
    assert_eq!(opened().succeeds(&predecessor_only()), Ok(()));
}

fn successor() -> Session {
    session_at(3, 1)
}

fn loaded() -> Suffix {
    Suffix {
        session: SESSION,
        start: 0,
        certified: END,
        end: END,
    }
}

/// The record represents [`successor`]'s target before that tenure reserves its own suffix.
fn predecessor_only() -> ShardRecord {
    ShardRecord {
        attempts: 2,
        ancestry: Ancestry::new(&[loaded()]).unwrap(),
        ..receipt(0)
    }
}

/// [`predecessor_only`] after [`successor`]'s tenure reserved its own suffix.
fn opened() -> ShardRecord {
    let own = Suffix {
        session: LATER_SESSION,
        start: END,
        certified: END,
        end: 64,
    };
    ShardRecord {
        ancestry: Ancestry::new(&[loaded(), own]).unwrap(),
        ..predecessor_only()
    }
}

fn unopened(kind: ExitKind) -> Planned {
    started(kind, &successor(), 0, deadline())
}

fn to_unopened(kind: ExitKind) -> Vec<Input> {
    let record = Input::Record(predecessor_only());
    let stop = match kind {
        ExitKind::Roll { publish: false } => vec![],
        _ => inputs(&[NO_SLOT]),
    };
    let tick = inputs(&[TICK]);
    [
        &[record][..],
        &tick,
        &stop,
        &[Input::Unopened],
        &inputs(&[CLEAR]),
    ]
    .concat()
}

#[test]
fn an_unopened_tenure_confirms_and_withdraws_with_no_seal_or_certify() {
    for kind in [ExitKind::Restart, ExitKind::Roll { publish: false }] {
        let mut planned = unopened(kind);
        let mut steps = run(&mut planned, &to_unopened(kind));
        steps.push(planned.step(Input::Clock(20)));
        assert_eq!(steps.last(), Some(&Step::Confirm), "{kind:?}: {steps:?}");
        assert_eq!(planned.step(Input::Clock(21)), Step::Wait, "one confirm");
        steps.push(planned.step(acknowledged(predecessor_only())));
        assert_eq!(
            steps.last(),
            Some(&Step::Withdraw(Then::Restart)),
            "{kind:?}"
        );
        let sealed = |step: &Step| matches!(step, Step::Seal | Step::Certify { .. });
        assert!(!steps.iter().any(sealed), "{kind:?}: {steps:?}");
        assert_eq!(
            planned.step(Input::Clock(22)),
            Step::Restart(Restart::Planned)
        );
    }
}

#[test]
fn each_check_false_alone_resumes_an_unopened_tenure() {
    let kind = ExitKind::Roll { publish: false };
    let good = predecessor_only();
    let floorless = Input::Certified(Certified::Acknowledged {
        record: good,
        floor: None,
    });
    let other_checkpoint = acknowledged(ShardRecord {
        checkpoint: Some(published_checkpoint()),
        ..good
    });
    let other_cut = acknowledged(ShardRecord { cut: 1, ..good });
    let unnamed = acknowledged(ShardRecord {
        standby: None,
        ..good
    });
    let cases = [
        ("W1 floor", floorless, Resume::Cut),
        ("W2 checkpoint", other_checkpoint, Resume::Cut),
        ("W2 cut", other_cut, Resume::Cut),
        ("an own suffix", acknowledged(opened()), Resume::Cut),
        ("W5 standby", unnamed, Resume::Standby),
        ("refused", Input::Certified(Certified::Refused), Resume::Cut),
        ("store", Input::Certified(Certified::Store), Resume::Store),
    ];
    for (name, confirm, reason) in cases {
        let mut planned = unopened(kind);
        let _ = run(&mut planned, &to_unopened(kind));
        assert_eq!(planned.step(Input::Clock(20)), Step::Confirm, "{name}");
        assert_eq!(planned.step(confirm), Step::Resume(reason), "{name}");
    }
    let mut open = unopened(kind);
    let _ = run(&mut open, &to_unopened(kind));
    let _ = open.step(Input::Coverage {
        acknowledgeable: true,
    });
    assert_eq!(open.step(Input::Clock(20)), Step::Confirm);
    assert_eq!(
        open.step(acknowledged(good)),
        Step::Resume(Resume::Cut),
        "W4"
    );
    let mut late = unopened(kind);
    let _ = run(&mut late, &to_unopened(kind));
    assert_eq!(
        late.step(Input::Clock(DEADLINE)),
        Step::Resume(Resume::Deadline),
        "W6"
    );
}

/// A transfer, a drain that published, and a drain whose seal was issued keep the seal and the certify, and an own
/// suffix certified below the durable end still resumes `cut`.
#[test]
fn every_other_drain_keeps_the_seal_and_the_certified_end() {
    let mut moved = machine(transfer());
    let _ = run(&mut moved, &inputs(&[RECORD, TICK, PUBLISHED]));
    assert_eq!(moved.step(Input::Unopened), Step::Wait);
    assert_eq!(moved.step(Input::Clock(20)), Step::Seal, "a transfer");
    let published = ExitKind::Roll { publish: true };
    let mut roll = machine(published);
    let _ = run(&mut roll, &inputs(&[RECORD, TICK, PUBLISHED]));
    assert_eq!(roll.step(Input::Unopened), Step::Wait);
    assert_eq!(roll.step(Input::Clock(20)), Step::Seal, "a published roll");
    let kind = ExitKind::Roll { publish: false };
    let mut sealed = machine(kind);
    let steps = run(&mut sealed, &to_sealed(kind));
    assert!(steps.contains(&Step::Seal), "{steps:?}");
    assert_eq!(sealed.step(Input::Unopened), Step::Wait);
    assert_eq!(sealed.step(Input::Clock(20)), Step::Wait, "no confirm");
    assert_eq!(sealed.step(settled(END)), Step::Certify { end: END });
    let short = acknowledged(receipt(END - 1));
    assert_eq!(sealed.step(short), Step::Resume(Resume::Cut));
}

#[test]
fn control_requiring_an_own_suffix_resumes_the_unopened_tenure() {
    let kind = ExitKind::Roll { publish: false };
    let step = with_plant(Plant::OwnSuffixRequired, || {
        let mut planned = unopened(kind);
        let _ = run(&mut planned, &to_unopened(kind));
        let _ = planned.step(Input::Clock(20));
        planned.step(acknowledged(predecessor_only()))
    });
    assert_eq!(step, Step::Resume(Resume::Cut), "FP-HAND-09");
}
