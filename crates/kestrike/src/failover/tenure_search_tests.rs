//! Tests of the tenure search. Two tests earn credit, each only for the bound it searches:
//! `the_record_search_exhausts_its_bound` at `BOUND` and
//! `the_transfer_search_exhausts_its_bound_and_reaches_the_target_s_bump` at `TRANSFER_BOUND`. The three controls of
//! the record search show a run that its credit rule refuses: a cap that stops the search, a bound with no fault and a
//! canonical form that merges states. The two controls of the transfer instance show the same for a cap below its
//! transitions and a handoff budget one attempt lower. Each of the record world's four plant tests breaks its named
//! monitor by one wrong decision or store arm in the model and replays the path without the plant to the production
//! reply, whose last step commits nothing: a refusal, or for `reread-after-unknown` an unknown outcome that leaves the
//! mints unchanged. The `transfer-keeps-e` plant breaks its monitor on a legal transfer, so its unplanted replay
//! commits the transfer at `E + 1`. The monitor table checks the mint clause of monitor 1 and the commit clauses of
//! monitors 2, 3 and 4, the step tests check the arms a write takes, the store effects the lost-reply and target-bump
//! witnesses require and the transfer's budget and refusal, the reply-contract test checks which replies end the
//! search, the ledger tests check the ledger's citations, and the stub model checks the search's exits and the
//! replay's `Disabled`, `Violation` and `Unexpected` exits.

use std::collections::BTreeSet;
use std::path::Path;

use super::flip::flipped;
use super::records::{CodecError, ShardRecord, SuccessorRule};
use super::retire::{Retirement, Role, Stale, Target, Trigger};
use super::search::{End, Model, Replay, Report, Seen, Totals, Verdict, control, replay, search};
use super::tenure_search::{
    Action, BOUND, BUMP_AFTER_LOST_COMMIT, BUMP_AT_OWN_GENERATION, Bound, CEILING, COPIED,
    Canonical, Commit, DECISIONS, Event, KINDS, Kind, LOST_AFTER_COMMIT, LOST_WITHOUT_COMMIT,
    NAMED_STANDBY_TAKES_OVER, NO_EPOCH_REUSE, PARKED, PARKED_COMMITTED_AT_RELEASE, Pending, Plant,
    Records, Reply, STALE_REQUEST_REFUSED, Side, TARGET_BUMP_AFTER_TRANSFER, TRANSFER_BOUND,
    TRANSFER_COMMITTED, TRANSFER_WITNESSES, WITNESSES, Writer, key, mint,
};
use crate::net::ownership::ShardGeneration;
use crate::storage::store::sim::Arm;
use crate::storage::store::{Refusal, Regression, StoreError, Version};
use crate::storage::store_tests::record;

/// A cap above the transitions of every search these tests run, so each search run with `CAP` ends by exhausting
/// its bound or by a failure.
const CAP: u64 = 10_000_000;

/// The totals of the unplanted search at [`BOUND`]: highest `E` 2, one lost or parked reply, one designation.
const PINNED: Totals = Totals {
    states: 30_731,
    transitions: 117_334,
    depth: 19,
};

const READ_A: Action = Action::Read(Side::A);
const READ_C: Action = Action::Read(Side::C);
const BUMP_A: Action = Action::Bump(Side::A, Arm::Pass);
const DROPPED_BUMP_A: Action = Action::Bump(Side::A, Arm::Timeout { commit: false });
const TAKEOVER_C: Action = Action::TakeOver(Side::C, Arm::Pass);
const FLIP: Action = Action::Flip(Arm::Pass);

const REREAD_AFTER_UNKNOWN: [Action; 2] = [READ_A, DROPPED_BUMP_A];
const UNNAMED_STANDBY: [Action; 2] = [READ_C, TAKEOVER_C];
const DOUBLE_WIN: [Action; 5] = [
    READ_A,
    Action::ReconcilerRead,
    Action::Request,
    FLIP,
    BUMP_A,
];
const RETIREMENT_UNADMITTED: [Action; 6] = [
    READ_A,
    Action::ReconcilerRead,
    BUMP_A,
    Action::Request,
    Action::ReconcilerRead,
    FLIP,
];

/// The names a credited search observes: its action kinds, its decisions and its witnesses.
struct Expected {
    totals: Totals,
    kinds: BTreeSet<&'static str>,
    decisions: BTreeSet<&'static str>,
    witnesses: BTreeSet<&'static str>,
}

/// The shared credit rule: an exhaustive search at `expected`'s totals that applied exactly its kinds, reached exactly
/// its decisions and observed exactly its witnesses.
fn earns(report: &Report<Action>, expected: &Expected) -> bool {
    let seen = &report.seen;
    report.verdict == Verdict::Exhaustive
        && report.totals == expected.totals
        && seen.kinds == expected.kinds
        && seen.decisions == expected.decisions
        && seen.witnesses == expected.witnesses
}

/// The record world's names at [`BOUND`]: the eight action kinds, the nine decisions and the thirteen witnesses.
fn record_world() -> Expected {
    Expected {
        totals: PINNED,
        kinds: KINDS.into_iter().collect(),
        decisions: DECISIONS.into_iter().collect(),
        witnesses: WITNESSES.into_iter().collect(),
    }
}

/// The credit rule of the record world at [`BOUND`].
fn credited(report: &Report<Action>) -> bool {
    earns(report, &record_world())
}

/// The search over every interleaving of the model's enabled actions for two hosts, the reconciler and the store's
/// request path at [`BOUND`] holds every monitor at every reached state and earns credit.
#[test]
fn the_record_search_exhausts_its_bound() {
    let report = search(&Records::new(Plant::None), CAP);
    println!(
        "tenure-record-search: {:?} {:?} kinds {} decisions {} witnesses {}",
        report.verdict,
        report.totals,
        report.seen.kinds.len(),
        report.seen.decisions.len(),
        report.seen.witnesses.len()
    );
    assert_eq!(report.verdict, Verdict::Exhaustive);
    assert_eq!(report.totals, PINNED);
    assert_eq!(report.seen.kinds, KINDS.into_iter().collect());
    assert_eq!(report.seen.decisions, DECISIONS.into_iter().collect());
    assert_eq!(report.seen.witnesses, WITNESSES.into_iter().collect());
    assert!(credited(&report));
}

/// Control for the credit rule: a search the cap stops has left states unexpanded, so its verdict earns nothing even
/// though every monitor held up to the cap.
#[test]
fn a_cap_below_the_pinned_transitions_ends_the_search_incomplete() {
    let report = search(&Records::new(Plant::None), PINNED.transitions - 1);
    assert_eq!(report.verdict, Verdict::Incomplete);
    assert_ne!(report.totals, PINNED);
    assert!(!credited(&report));
}

/// Control for the witness rule: an exhaustive search of a bound that loses and parks no reply passes every monitor
/// while the store never exercised its unknown-outcome arms, and the missing lost-reply witnesses withhold its credit.
#[test]
fn a_bound_without_faults_misses_the_lost_reply_witnesses() {
    let records = Records {
        bound: Bound { faults: 0, ..BOUND },
        ..Records::new(Plant::None)
    };
    let report = search(&records, CAP);
    assert_eq!(report.verdict, Verdict::Exhaustive);
    for witness in [LOST_AFTER_COMMIT, LOST_WITHOUT_COMMIT, PARKED] {
        assert!(!report.seen.witnesses.contains(witness), "{witness}");
    }
    let mut pinned = Report {
        totals: PINNED,
        ..report
    };
    pinned.seen.kinds = KINDS.into_iter().collect();
    pinned.seen.decisions = DECISIONS.into_iter().collect();
    assert!(!credited(&pinned));
}

/// Control for the canonical form: a parked write changes what a later release commits, so a form that leaves it out
/// merges each held write's world with the dropped write's world, which the action order reaches first. The search
/// then stores fewer states than the pinned count, never applies a release and never sees a parked write commit.
#[test]
fn a_canonical_form_without_the_parked_write_reaches_fewer_states() {
    let records = Records {
        canonical: Canonical::WithoutParked,
        ..Records::new(Plant::None)
    };
    let report = search(&records, CAP);
    assert_eq!(report.verdict, Verdict::Exhaustive);
    assert!(report.totals.states < PINNED.states, "{:?}", report.totals);
    assert!(!report.seen.kinds.contains("Release"));
    assert!(!report.seen.witnesses.contains(PARKED_COMMITTED_AT_RELEASE));
    assert!(!credited(&report));
}

/// The planted search and the planted replay of `path` with one more action must break `property` along `path`; the
/// unplanted replay of `path` applies every step with every monitor holding, and the plant's step, its last, returns
/// `reply` and commits nothing. Returns the unplanted replay.
fn planted(
    plant: Plant,
    property: &'static str,
    path: &[Action],
    reply: &Reply,
) -> Replay<Records> {
    let broken = Records::new(plant);
    let replayed = control(&broken, &Records::new(Plant::None), CAP, property, path);
    let longer = [path, &[READ_A]].concat();
    assert_eq!(
        replay(&broken, &longer).end,
        End::Violation {
            property,
            path: path.to_vec()
        }
    );
    let last = replayed.last();
    assert_eq!(&last.reply, reply);
    assert_eq!(last.commit, None, "{:?}", last.reply);
    replayed
}

/// Plant `reread-after-unknown`: after a write whose outcome is unknown, the host rereads the record and records the
/// tenure the record assigns it as a mint. The search reports "NoEpochReuse" at A's dropped bump, whose reread mints
/// the root tenure a second time. In the unplanted replay the bump returns `StoreError::Unknown` and the mints stay
/// the root's.
#[test]
fn a_reread_after_an_unknown_outcome_breaks_no_epoch_reuse() {
    let replayed = planted(
        Plant::RereadAfterUnknown,
        "NoEpochReuse",
        &REREAD_AFTER_UNKNOWN,
        &Reply::Refused(StoreError::Unknown),
    );
    let root = Records::new(Plant::None).root();
    assert_eq!(replayed.world.mints(), root.mints());
}

/// Plant `unnamed-standby`: a host the record leaves unnamed as standby writes the takeover value by a raw
/// exact-version write in place of `Client::take_over`. The search reports "NamedStandbyTakesOver" when C's write
/// commits over a record whose standby field is empty. In the unplanted replay `Client::take_over` refuses with
/// `StoreError::Stale(Stale::Target)`, and the step commits nothing.
#[test]
fn an_unnamed_host_takeover_breaks_named_standby_takes_over() {
    planted(
        Plant::UnnamedStandby,
        "NamedStandbyTakesOver",
        &UNNAMED_STANDBY,
        &Reply::Refused(StoreError::Stale(Stale::Target)),
    );
}

/// Plant `double-win`: the store applies a host's bump over a failed condition (`Arm::DoubleWin`). The search reports
/// "BumpAtOwnGeneration" when A's bump, conditioned on its read before the flip, commits over the flipped record. In
/// the unplanted replay the bump returns `StoreError::Refused(Refusal::Condition)`.
#[test]
fn a_bump_applied_over_its_failed_condition_breaks_bump_at_own_generation() {
    planted(
        Plant::DoubleWin,
        "BumpAtOwnGeneration",
        &DOUBLE_WIN,
        &Reply::Refused(StoreError::Refused(Refusal::Condition)),
    );
}

/// Plant `retirement-unadmitted`: the reconciler flips through `Client::flip` and skips `Retirement::admit`. The
/// search reports "StaleRequestRefused" when the reconciler flips A's bumped tenure on a request built for the tenure
/// before the bump. In the unplanted replay `Retirement::admit` refuses the request with `Stale::Target`, and the
/// flip ends before its write.
#[test]
fn a_flip_without_admission_breaks_stale_request_refused() {
    planted(
        Plant::RetirementUnadmitted,
        "StaleRequestRefused",
        &RETIREMENT_UNADMITTED,
        &Reply::Unadmitted(Stale::Target),
    );
}

/// The model enables only the arms it schedules: after A's read, with a fault left, A's bump is enabled under `Pass`
/// and the lost and parked arms and disabled under each of the store double's ten other arms, and a replay of the
/// bump under `Arm::LostWrite` ends at that action with only the read applied and the mints the root's.
#[test]
fn a_write_takes_only_the_arms_the_model_schedules() {
    let records = Records::new(Plant::None);
    let read = replay(&records, &[READ_A]).world;
    for arm in [
        Arm::Pass,
        Arm::Timeout { commit: true },
        Arm::Timeout { commit: false },
        Arm::Hold,
    ] {
        assert!(
            records.enabled(&read, Action::Bump(Side::A, arm)),
            "{arm:?}"
        );
    }
    for arm in [
        Arm::Delay,
        Arm::Reorder,
        Arm::Duplicate,
        Arm::Failure { commit: true },
        Arm::Failure { commit: false },
        Arm::Unavailable,
        Arm::StaleRead,
        Arm::LostWrite,
        Arm::DoubleWin,
        Arm::StaleCurrentRead,
    ] {
        assert!(
            !records.enabled(&read, Action::Bump(Side::A, arm)),
            "{arm:?}"
        );
    }
    let lost_write = Action::Bump(Side::A, Arm::LostWrite);
    let replayed = replay(&records, &[READ_A, lost_write]);
    assert_eq!(
        replayed.end,
        End::Disabled {
            at: 1,
            action: lost_write
        }
    );
    assert_eq!(replayed.events.len(), 1);
    assert_eq!(replayed.world.mints(), records.root().mints());
}

/// A lost-reply witness needs its arm label and the store effect that label names: neither a commit nor a parked
/// write for `LOST_WITHOUT_COMMIT`, and a parked write without a commit for `PARKED`. Three cases step A's bump from
/// the world after A's read with another arm scheduled ahead of the action's own, so the reply is unknown, the mints
/// stay the root's, and the store's effect differs from the label. Deleting the commit guard of
/// `LOST_WITHOUT_COMMIT` or the queue guards of either witness makes a case record its witness. A write the store
/// parks under any label becomes the world's parked write, which the release commits, and a held-label write the
/// store drops shares the canonical form of a dropped-label write the store drops.
#[test]
fn lost_reply_witnesses_follow_the_store_effect() {
    let records = Records::new(Plant::None);
    let read = replay(&records, &[READ_A]).world;
    let step = |scheduled: Arm, action: Action| {
        let mut world = read.clone();
        world.schedule(scheduled);
        let mut seen = Seen::default();
        let (next, event) = records
            .step(&world, action, &mut seen)
            .expect("an unknown reply");
        assert_eq!(event.reply, Reply::Refused(StoreError::Unknown));
        assert_eq!(next.mints(), read.mints());
        (next, event, seen)
    };
    let dropped = Action::Bump(Side::A, Arm::Timeout { commit: false });
    let held = Action::Bump(Side::A, Arm::Hold);

    let (_, event, seen) = step(Arm::Timeout { commit: true }, dropped);
    assert!(event.commit.is_some());
    assert!(!seen.witnesses.contains(LOST_WITHOUT_COMMIT));

    let (queued, event, seen) = step(Arm::Hold, dropped);
    assert_eq!(event.commit, None);
    assert!(!seen.witnesses.contains(LOST_WITHOUT_COMMIT));
    assert!(records.enabled(&queued, Action::Release));
    let (_, release) = records
        .step(&queued, Action::Release, &mut Seen::default())
        .expect("the release applies the parked bump");
    let commit = release
        .commit
        .expect("the parked bump commits at its release");
    assert_eq!(
        (commit.pending.kind, commit.pending.writer),
        (Kind::Bump, Writer::Host(Side::A))
    );

    let (unqueued, event, seen) = step(Arm::Timeout { commit: false }, held);
    assert_eq!(event.commit, None);
    assert!(!seen.witnesses.contains(PARKED));
    assert!(!records.enabled(&unqueued, Action::Release));
    let (truly_dropped, ..) = step(Arm::Timeout { commit: false }, dropped);
    assert!(records.canonical(&unqueued) == records.canonical(&truly_dropped));
}

/// The monitors judge hand-built commits and mints at the root world. Each conforming input passes, and each row
/// breaks one clause of one monitor and keeps every other clause true. The rows test the mint clause of monitor 1 and
/// the commit clauses of monitors 2, 3 and 4, a transfer's generation among them, and a transfer step's earlier bump
/// commit judged beside its transfer; the plant tests show production decisions reaching them.
#[test]
fn each_monitor_clause_fails_its_own_commit() {
    let records = Records::new(Plant::None);
    let world = records.root();
    let generation = |g: u64| ShardGeneration::new(g).expect("nonzero generation");
    let (spare, _) = record().spare.expect("the root record names a spare");
    let a = Side::A.host();
    let c = Side::C.host();

    let [root] = world.mints() else {
        unreachable!("the root holds one mint")
    };
    let minted = |target: Target| {
        let mut minted = world.clone();
        mint(&mut minted, target);
        records.monitor(&minted, None)
    };
    assert_eq!(
        minted(Target {
            owner: c,
            attempts: root.attempts + 1,
            ..*root
        }),
        None
    );
    assert_eq!(minted(Target { owner: c, ..*root }), Some(NO_EPOCH_REUSE));

    let named = ShardRecord {
        attempts: 1,
        standby: Some(c),
        ..record()
    };
    let commit = |kind: Kind,
                  read: ShardRecord,
                  below: ShardRecord,
                  written: ShardRecord,
                  request: Option<Retirement>| Event {
        reply: Reply::Done,
        earlier: None,
        commit: Some(Commit {
            below,
            written,
            pending: Pending {
                kind,
                writer: Writer::Reconciler,
                read,
                expect: Version::FIRST,
                request,
            },
        }),
    };
    let judge = |event: &Event| records.monitor(&world, Some(event));
    let stale = ShardRecord {
        generation: generation(2),
        ..named
    };

    let taken = ShardRecord {
        owner: c,
        attempts: 2,
        standby: None,
        ..named
    };
    let takeover = |below: ShardRecord, written: ShardRecord| {
        judge(&commit(Kind::TakeOver, below, below, written, None))
    };
    assert_eq!(takeover(named, taken), None);
    let rows = [
        (
            "an empty standby below",
            ShardRecord {
                standby: None,
                ..named
            },
            taken,
        ),
        (
            "a standby below naming another host",
            ShardRecord {
                standby: Some(a),
                ..named
            },
            taken,
        ),
        (
            "E = 0 below",
            ShardRecord {
                attempts: 0,
                ..named
            },
            ShardRecord {
                attempts: 1,
                ..taken
            },
        ),
        (
            "E + 2 written",
            named,
            ShardRecord {
                attempts: 3,
                ..taken
            },
        ),
        (
            "E kept",
            named,
            ShardRecord {
                attempts: 1,
                ..taken
            },
        ),
        (
            "a standby written",
            named,
            ShardRecord {
                standby: Some(a),
                ..taken
            },
        ),
        (
            "another volume written",
            named,
            ShardRecord {
                active: spare,
                ..taken
            },
        ),
    ];
    for (row, below, written) in rows {
        assert_eq!(
            takeover(below, written),
            Some(NAMED_STANDBY_TAKES_OVER),
            "{row}"
        );
    }

    let bumped = ShardRecord {
        attempts: 2,
        ..named
    };
    assert_eq!(judge(&commit(Kind::Bump, named, named, bumped, None)), None);
    assert_eq!(
        judge(&commit(Kind::Bump, stale, named, bumped, None)),
        Some(BUMP_AT_OWN_GENERATION)
    );
    assert_eq!(
        judge(&commit(Kind::TakeOver, stale, named, taken, None)),
        Some(BUMP_AT_OWN_GENERATION)
    );
    assert_eq!(
        judge(&commit(Kind::Transfer, named, named, taken, None)),
        None
    );
    assert_eq!(
        judge(&commit(Kind::Transfer, stale, named, taken, None)),
        Some(BUMP_AT_OWN_GENERATION)
    );
    let transfer_step = |earlier: Event| Event {
        earlier: earlier.commit,
        ..commit(
            Kind::Transfer,
            bumped,
            bumped,
            ShardRecord {
                attempts: 3,
                ..taken
            },
            None,
        )
    };
    assert_eq!(
        judge(&transfer_step(commit(
            Kind::Bump,
            named,
            named,
            bumped,
            None
        ))),
        None
    );
    assert_eq!(
        judge(&transfer_step(commit(
            Kind::Bump,
            stale,
            named,
            bumped,
            None
        ))),
        Some(BUMP_AT_OWN_GENERATION),
        "the transfer step's bump is judged beside its transfer"
    );
    let unnamed_below = ShardRecord {
        owner: c,
        standby: None,
        ..named
    };
    assert_eq!(
        judge(&transfer_step(commit(
            Kind::Bump,
            unnamed_below,
            unnamed_below,
            bumped,
            None
        ))),
        Some(NAMED_STANDBY_TAKES_OVER),
        "an earlier owner change over a value naming no standby"
    );
    assert_eq!(
        judge(&transfer_step(commit(
            Kind::Bump,
            stale,
            stale,
            bumped,
            None
        ))),
        Some(STALE_REQUEST_REFUSED),
        "an earlier commit raising the generation with no request"
    );

    let flip = flipped(&named).expect("the named record flips to its spare");
    let request = |target: Target, volume| {
        Retirement::new(volume, Role::Active, target, Trigger::VolumeState)
    };
    let served = Target::of(&named);
    let flips = |request| judge(&commit(Kind::Flip, named, named, flip, request));
    assert_eq!(flips(request(served, named.active)), None);
    let rows = [
        ("no request", None),
        (
            "another generation",
            request(
                Target {
                    generation: generation(2),
                    ..served
                },
                named.active,
            ),
        ),
        (
            "another owner",
            request(Target { owner: c, ..served }, named.active),
        ),
        (
            "another E",
            request(
                Target {
                    attempts: 2,
                    ..served
                },
                named.active,
            ),
        ),
        ("the spare volume", request(served, spare)),
    ];
    for (row, request) in rows {
        assert_eq!(flips(request), Some(STALE_REQUEST_REFUSED), "{row}");
    }
}

/// A reply outside what an unplanted record world returns makes `Records::expected` and the step return `Err` naming
/// the action and the reply, which ends a search as `Verdict::Unexpected`; under the `double-win` plant the client's
/// `Regression` is the plant's expected reply.
#[test]
fn an_unplanted_world_fails_on_a_reply_outside_its_contract() {
    let unplanted = Records::new(Plant::None);
    let regression = Reply::Refused(StoreError::Regression(Regression::Value(key())));
    let failure = unplanted
        .expected(BUMP_A, &regression)
        .expect_err("an unplanted Regression ends the search");
    assert!(
        failure.contains("Bump(A, Pass)") && failure.contains("Regression"),
        "{failure}"
    );
    for error in [
        StoreError::Withdrawn,
        StoreError::Log,
        StoreError::Codec(CodecError::Length),
        StoreError::Successor(SuccessorRule::Identity),
        StoreError::Namespace,
    ] {
        let failure = unplanted
            .expected(FLIP, &Reply::Refused(error))
            .expect_err("an unplanted reply outside the world's contract ends the search");
        assert!(
            failure.contains("Flip(Pass)") && failure.contains(&format!("{error:?}")),
            "{failure}"
        );
        let planted = Records::new(Plant::DoubleWin).expected(FLIP, &Reply::Refused(error));
        assert!(planted.is_err(), "{error:?}");
    }
    let mut world = unplanted.root();
    world.schedule(Arm::StaleCurrentRead);
    let refused = unplanted
        .step(&world, READ_A, &mut Seen::default())
        .err()
        .expect("a read below A's watermark withdraws its client");
    assert!(
        refused.contains("Read(A)") && refused.contains("Regression"),
        "{refused}"
    );
    let unknown = Reply::Refused(StoreError::Unknown);
    assert_eq!(unplanted.expected(BUMP_A, &unknown), Ok(()));
    assert_eq!(
        Records::new(Plant::DoubleWin).expected(BUMP_A, &regression),
        Ok(())
    );
}

/// The ledger's existence check: a declaration of `function` as a direct item of an inherent impl of `owner`. An
/// impl header opens the scope when the line starts with `impl` at column 0, holds no ` for `, ends with the brace
/// that opens the body, and its self type, after `impl` and its generic parameters, is `owner` followed by `<` or
/// ` {`; a line holding only `}` closes it. A declaration is a line at the impl's item depth, four spaces, whose code
/// after an optional `pub` or `pub(...)` and any of `const`, `async` and `unsafe` starts with `fn function(` or
/// `fn function<`. A `#[cfg(test)]` line directly above the impl header or the declaration excludes it. The check
/// reads lines: a line comment never matches, and a block-comment or string-literal line that matches counts as a
/// declaration.
fn defines(source: &str, owner: &str, function: &str) -> bool {
    let header = |line: &str| {
        let Some(rest) = line.strip_prefix("impl") else {
            return false;
        };
        let self_type = match rest.strip_prefix('<') {
            Some(generics) => {
                let mut depth = 1_usize;
                let close = generics.char_indices().find_map(|(at, ch)| {
                    match ch {
                        '<' => depth += 1,
                        '>' => depth -= 1,
                        _ => {}
                    }
                    (depth == 0).then_some(at)
                });
                close.map_or("", |at| &generics[at + 1..])
            }
            None => rest,
        };
        let self_type = self_type.trim_start();
        !line.contains(" for ")
            && line.ends_with('{')
            && (self_type.starts_with(&format!("{owner}<"))
                || self_type.starts_with(&format!("{owner} {{")))
    };
    let declares = |line: &str| {
        let Some(code) = line.strip_prefix("    ") else {
            return false;
        };
        let mut code = code;
        if let Some(rest) = code.strip_prefix("pub") {
            code = match rest.strip_prefix('(') {
                Some(scoped) => scoped.split_once(") ").map_or("", |(_, rest)| rest),
                None => rest.strip_prefix(' ').unwrap_or(code),
            };
        }
        while let Some(rest) = ["const ", "async ", "unsafe "]
            .iter()
            .find_map(|qualifier| code.strip_prefix(qualifier))
        {
            code = rest;
        }
        code.starts_with(&format!("fn {function}(")) || code.starts_with(&format!("fn {function}<"))
    };
    let gated = |line: &str| line.trim() == "#[cfg(test)]";
    let mut inside = false;
    let mut previous = "";
    for line in source.lines() {
        if header(line) {
            inside = !gated(previous);
        } else if line == "}" {
            inside = false;
        } else if inside && declares(line) && !gated(previous) {
            return true;
        }
        previous = line;
    }
    false
}

#[test]
fn the_ledger_check_finds_a_direct_declaration_and_nothing_else() {
    for declared in [
        "impl<S: Store, L: WatermarkLog> Reconciler<S, L> {\n    pub fn flip_for(&mut self) {}\n}\n",
        "impl Reconciler {\n    fn flip_for(&mut self) {}\n}\n",
        "impl Reconciler {\n    pub(super) fn flip_for(&mut self) {}\n}\n",
        "impl Reconciler {\n    pub(in crate::failover) const fn flip_for() {}\n}\n",
        "impl Reconciler {\n    async unsafe fn flip_for<T>() {}\n}\n",
    ] {
        assert!(defines(declared, "Reconciler", "flip_for"), "{declared}");
    }
    let generic = "impl Restart<'_> {\n    fn records<S: Store>(\n    ) {}\n}\n";
    assert!(defines(generic, "Restart", "records"));
    for absent in [
        "impl Reconciler<S> {\n    // fn flip_for(&mut self) {}\n}\n",
        "impl Reconciler<S> {\n    /// See `pub fn flip_for(`.\n}\n",
        "impl Reconciler<S> {\n    fn other() {} // fn flip_for(\n}\n",
        "impl Other {\n    pub fn flip_for(&mut self) {}\n}\n",
        "impl Other<Reconciler> {\n    pub fn flip_for(&mut self) {}\n}\n",
        "impl<T: Reconciler> Other<T> {\n    pub fn flip_for(&mut self) {}\n}\n",
        "impl Reconciler {\n    fn other() {\n        fn flip_for() {}\n    }\n}\n",
        "impl Reconciler {}\nimpl Other {\n    fn flip_for() {}\n}\n",
        "impl Reconciler {\n    fn other() {}\n}\nimpl Other {\n    fn flip_for() {}\n}\n",
        "impl Flip for Reconciler {\n    fn flip_for(&mut self) {}\n}\n",
        "#[cfg(test)]\nimpl Reconciler {\n    fn flip_for(&mut self) {}\n}\n",
        "impl Reconciler {\n    #[cfg(test)]\n    fn flip_for(&mut self) {}\n}\n",
    ] {
        assert!(!defines(absent, "Reconciler", "flip_for"), "{absent}");
    }
}

/// The ledger caps the rules the model restates from production: an entry added without a matching ceiling fails
/// here, and so does an entry whose cited function has no declaration that [`defines`] finds. The test reads each
/// symbol's name and leaves the rule the symbol holds unjudged.
#[test]
fn the_ledger_holds_exactly_its_ceiling() {
    assert_eq!(COPIED.len(), CEILING);
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/failover");
    for entry in COPIED {
        assert!(
            !entry.rule.is_empty() && !entry.sites.is_empty(),
            "{}",
            entry.name
        );
        for site in entry.sites {
            let source =
                std::fs::read_to_string(root.join(site.file)).expect("a cited source file");
            assert!(
                defines(&source, site.owner, site.function),
                "{}: {}::{} is absent from {}",
                entry.name,
                site.owner,
                site.function,
                site.file
            );
        }
    }
}

/// A model over the worlds 0, 1 and 2: action 0 advances the world, action 1 keeps it, and no action is enabled at
/// 2, so a search applies four transitions and stores three states. With `refuse`, action 1 at world 1 returns a
/// refusal; the monitor rejects the world `broken` names.
#[derive(Default)]
struct Stub {
    refuse: bool,
    broken: Option<u8>,
}

impl Model for Stub {
    type World = u8;
    type Action = u8;
    type Event = ();
    type Canon = u8;

    fn root(&self) -> u8 {
        0
    }

    fn alphabet(&self) -> &[u8] {
        &[0, 1]
    }

    fn enabled(&self, world: &u8, _: u8) -> bool {
        *world < 2
    }

    fn kind(&self, action: u8) -> &'static str {
        if action == 0 { "advance" } else { "stay" }
    }

    fn step(&self, world: &u8, action: u8, _: &mut Seen) -> Result<(u8, ()), String> {
        match (*world, action) {
            (1, 1) if self.refuse => Err("refused at 1".to_owned()),
            (world, 0) => Ok((world + 1, ())),
            (world, _) => Ok((world, ())),
        }
    }

    fn monitor(&self, world: &u8, _: Option<&()>) -> Option<&'static str> {
        (self.broken == Some(*world)).then_some("Broken")
    }

    fn canonical(&self, world: &u8) -> u8 {
        *world
    }
}

#[test]
fn a_step_that_returns_a_refusal_ends_the_search_and_the_replay_unexpected() {
    let refusing = Stub {
        refuse: true,
        ..Stub::default()
    };
    let (refusal, path) = ("refused at 1".to_owned(), vec![0, 1]);
    assert_eq!(
        search(&refusing, CAP).verdict,
        Verdict::Unexpected {
            refusal: refusal.clone(),
            path: path.clone()
        }
    );
    assert_eq!(
        replay(&refusing, &[0, 1, 0]).end,
        End::Unexpected { refusal, path }
    );
}

#[test]
fn a_cap_equal_to_the_transitions_exhausts_and_one_less_ends_incomplete() {
    let exhausted = search(&Stub::default(), 4);
    assert_eq!(exhausted.verdict, Verdict::Exhaustive);
    let totals = Totals {
        states: 3,
        transitions: 4,
        depth: 2,
    };
    assert_eq!(exhausted.totals, totals);
    assert_eq!(search(&Stub::default(), 3).verdict, Verdict::Incomplete);
}

#[test]
fn a_broken_root_ends_the_search_and_the_replay_with_an_empty_path() {
    let broken = Stub {
        broken: Some(0),
        ..Stub::default()
    };
    assert_eq!(
        search(&broken, CAP).verdict,
        Verdict::Violation {
            property: "Broken",
            path: Vec::new()
        }
    );
    let replayed = replay(&broken, &[0]);
    assert_eq!(
        replayed.end,
        End::Violation {
            property: "Broken",
            path: Vec::new()
        }
    );
    assert!(replayed.events.is_empty());
}

#[test]
fn a_replay_stops_at_a_disabled_action_or_one_outside_the_alphabet() {
    let disabled = replay(&Stub::default(), &[0, 0, 0]);
    assert_eq!(disabled.end, End::Disabled { at: 2, action: 0 });
    assert_eq!((disabled.events.len(), disabled.world), (2, 2));
    let outside = replay(&Stub::default(), &[0, 7]);
    assert_eq!(outside.end, End::Disabled { at: 1, action: 7 });
    assert_eq!((outside.events.len(), outside.world), (1, 1));
}

/// The transfer instance: A's planned transfer as one more step of the record world at [`TRANSFER_BOUND`].
fn transfer_records(plant: Plant) -> Records {
    Records {
        bound: TRANSFER_BOUND,
        ..Records::new(plant)
    }
}

/// The totals of the transfer instance at [`TRANSFER_BOUND`]: highest `E` 2 below the handoff, A's one transfer, no
/// lost or parked reply, one designation.
const TRANSFER_PINNED: Totals = Totals {
    states: 3_448,
    transitions: 10_242,
    depth: 18,
};

const TRANSFER_A: Action = Action::Transfer(Side::A);

/// The shortest path to the `transfer-keeps-e` plant's violation: the reconciler names C standby, and A reads and
/// transfers.
const TRANSFER_KEEPS_E: [Action; 4] = [
    Action::ReconcilerRead,
    Action::Designate(Arm::Pass),
    READ_A,
    TRANSFER_A,
];

/// The transfer instance's names: the record world's action kinds without `Release`, which no parked write enables,
/// and with `Transfer`; the record world's decisions and `Client::transfer`; and the eight transfer witnesses.
fn transfer_instance() -> Expected {
    let mut kinds: BTreeSet<_> = KINDS.into_iter().collect();
    kinds.remove("Release");
    kinds.insert("Transfer");
    let mut decisions: BTreeSet<_> = DECISIONS.into_iter().collect();
    decisions.insert("Client::transfer");
    Expected {
        totals: TRANSFER_PINNED,
        kinds,
        decisions,
        witnesses: TRANSFER_WITNESSES.into_iter().collect(),
    }
}

/// The credit rule of the transfer instance at [`TRANSFER_BOUND`].
fn transfer_credited(report: &Report<Action>) -> bool {
    earns(report, &transfer_instance())
}

/// The record world with A's planned transfer as one more step at [`TRANSFER_BOUND`] holds every monitor at every
/// reached state, calls `Client::transfer` on the committed read of A's own bump, and reaches both the committed
/// transfer and the target C's own bump of the transferred record.
#[test]
fn the_transfer_search_exhausts_its_bound_and_reaches_the_target_s_bump() {
    let report = search(&transfer_records(Plant::None), CAP);
    println!(
        "tenure-transfer-search: {:?} {:?} kinds {} decisions {} witnesses {}",
        report.verdict,
        report.totals,
        report.seen.kinds.len(),
        report.seen.decisions.len(),
        report.seen.witnesses.len()
    );
    let expected = transfer_instance();
    assert_eq!(report.verdict, Verdict::Exhaustive);
    assert_eq!(report.totals, TRANSFER_PINNED);
    assert_eq!(report.seen.kinds, expected.kinds);
    assert_eq!(report.seen.decisions, expected.decisions);
    assert_eq!(report.seen.witnesses, expected.witnesses);
    assert!(transfer_credited(&report));
}

/// Control for the attempt budget: one handoff writes the transfer's attempt and C's bump above the top, so with one
/// attempt fewer C's bump of the transferred record is never enabled and the reach witness is missing. The report
/// with the pinned totals, kinds and decisions is refused on its witness set alone: adding the missing witness back
/// earns the credit.
#[test]
fn a_handoff_budget_one_attempt_lower_never_reaches_the_target_s_bump() {
    let records = Records {
        bound: Bound {
            handoff: TRANSFER_BOUND.handoff - 1,
            ..TRANSFER_BOUND
        },
        ..Records::new(Plant::None)
    };
    let report = search(&records, CAP);
    assert_eq!(report.verdict, Verdict::Exhaustive);
    assert!(report.seen.witnesses.contains(TRANSFER_COMMITTED));
    assert!(!report.seen.witnesses.contains(TARGET_BUMP_AFTER_TRANSFER));
    assert!(!transfer_credited(&report));
    let expected = transfer_instance();
    let mut pinned = Report {
        totals: TRANSFER_PINNED,
        ..report
    };
    pinned.seen.kinds = expected.kinds;
    pinned.seen.decisions = expected.decisions;
    assert!(!transfer_credited(&pinned));
    pinned.seen.witnesses.insert(TARGET_BUMP_AFTER_TRANSFER);
    assert!(transfer_credited(&pinned));
}

/// Control for the credit rule: a cap one below the pinned transitions ends the transfer search incomplete.
#[test]
fn a_cap_below_the_transfer_search_s_transitions_ends_it_incomplete() {
    let report = search(
        &transfer_records(Plant::None),
        TRANSFER_PINNED.transitions - 1,
    );
    assert_eq!(report.verdict, Verdict::Incomplete);
    assert!(!transfer_credited(&report));
}

/// Plant `transfer-keeps-e`: A's transfer writes the production transfer value with the bump's `E` by a raw
/// exact-version write. The search reports "NamedStandbyTakesOver" along the pinned shortest path. A transfer over a
/// read naming the target standby is a legal write, so the unplanted replay of that path commits it, unlike the record
/// world's plants, whose replays end at a refusal: A's bump from `E = 1` to `E = 2`, then the transfer to C at
/// `E = 3`, acknowledged, with A's two tenures the only mints. C's read and bump then mint C at `E = 4`.
#[test]
fn a_transfer_that_keeps_e_breaks_named_standby_takes_over() {
    let unplanted = transfer_records(Plant::None);
    let replayed = control(
        &transfer_records(Plant::TransferKeepsE),
        &unplanted,
        CAP,
        "NamedStandbyTakesOver",
        &TRANSFER_KEEPS_E,
    );
    let last = replayed.last();
    assert_eq!(last.reply, Reply::Done);
    let (a, c) = (Side::A.host(), Side::C.host());
    let generation = record().generation;
    let tenure = |owner, attempts| Target {
        generation,
        owner,
        attempts,
    };
    assert_eq!(unplanted.root().mints(), [tenure(a, 1)]);
    let bump = last.earlier.as_ref().expect("A's bump committed");
    assert_eq!(bump.pending.kind, Kind::Bump);
    assert_eq!(
        (
            bump.below.owner,
            bump.below.attempts,
            bump.written.owner,
            bump.written.attempts
        ),
        (a, 1, a, 2)
    );
    let transfer = last.commit.as_ref().expect("the transfer committed");
    assert_eq!(transfer.pending.kind, Kind::Transfer);
    assert_eq!(transfer.below, bump.written);
    assert_eq!(
        (
            transfer.written.owner,
            transfer.written.attempts,
            transfer.written.standby
        ),
        (c, 3, None)
    );
    assert_eq!(replayed.world.mints(), [tenure(a, 1), tenure(a, 2)]);

    let handed = replay(
        &unplanted,
        &[
            TRANSFER_KEEPS_E.as_slice(),
            &[READ_C, Action::Bump(Side::C, Arm::Pass)],
        ]
        .concat(),
    );
    assert_eq!(handed.end, End::Applied);
    let last = handed.last();
    assert_eq!(last.reply, Reply::Done);
    let bump = last.commit.as_ref().expect("C's bump committed");
    assert_eq!(
        (bump.pending.kind, bump.written.owner, bump.written.attempts),
        (Kind::Bump, c, 4)
    );
    assert_eq!(
        handed.world.mints(),
        [tenure(a, 1), tenure(a, 2), tenure(c, 4)]
    );
}

/// The target-bump witness follows the store's effect: from the committed transfer and C's read of the transferred
/// tenure, C's bump above the top commits `E + 1` over that record and records the witness in its own step, and the
/// same bump after the reconciler's flip is still enabled, refuses on its condition, commits nothing and records no
/// witness.
#[test]
fn the_target_s_bump_earns_its_witness_only_when_it_commits() {
    let records = transfer_records(Plant::None);
    let bump_c = Action::Bump(Side::C, Arm::Pass);
    let handed = [TRANSFER_KEEPS_E.as_slice(), &[READ_C]].concat();
    let read = replay(&records, &handed);
    assert_eq!(read.end, End::Applied);
    let transferred = *read.world.record();
    assert_eq!(
        (transferred.owner, transferred.attempts),
        (Side::C.host(), 3)
    );
    assert!(transferred.attempts >= TRANSFER_BOUND.top);
    assert_eq!(read.world.handed(), Some(Target::of(&transferred)));
    assert!(records.enabled(&read.world, bump_c));
    let mut seen = Seen::default();
    let (next, event) = records
        .step(&read.world, bump_c, &mut seen)
        .expect("C's bump applies");
    assert_eq!(event.reply, Reply::Done);
    let commit = event.commit.expect("C's bump committed");
    assert_eq!(
        (commit.pending.kind, commit.pending.writer),
        (Kind::Bump, Writer::Host(Side::C))
    );
    assert_eq!(commit.below, transferred);
    assert_eq!(commit.written.attempts, transferred.attempts + 1);
    assert!(seen.witnesses.contains(TARGET_BUMP_AFTER_TRANSFER));
    assert_eq!(next.handed(), None);

    let flipped = [
        handed.as_slice(),
        &[Action::ReconcilerRead, Action::Request, FLIP],
    ]
    .concat();
    let stale = replay(&records, &flipped);
    assert_eq!(stale.end, End::Applied);
    assert!(stale.last().commit.is_some());
    assert!(records.enabled(&stale.world, bump_c));
    let mut seen = Seen::default();
    let (_, event) = records
        .step(&stale.world, bump_c, &mut seen)
        .expect("C's stale bump refuses");
    assert_eq!(
        event.reply,
        Reply::Refused(StoreError::Refused(Refusal::Condition))
    );
    assert_eq!((event.commit, event.earlier), (None, None));
    assert!(!seen.witnesses.contains(TARGET_BUMP_AFTER_TRANSFER));
}

/// `Client::transfer` decides the standby clause. Each case steps A's enabled transfer with a fresh `Seen`: over a read
/// naming no standby the step calls `Client::transfer`, which returns `Stale::Target` before its request, so A's bump
/// is the step's one commit and mint, no tenure is handed and no transfer is spent; over the read after the
/// reconciler names C, the same step commits the bump and then the transfer to C at `E + 1` and records the transfer
/// witness.
#[test]
fn a_transfer_over_a_read_naming_no_standby_refuses_after_the_bump() {
    let records = transfer_records(Plant::None);
    let step = |path: &[Action]| {
        let before = replay(&records, path);
        assert_eq!(before.end, End::Applied);
        assert!(records.enabled(&before.world, TRANSFER_A));
        let mut seen = Seen::default();
        let (next, event) = records
            .step(&before.world, TRANSFER_A, &mut seen)
            .expect("the transfer step applies");
        assert_eq!(records.monitor(&next, Some(&event)), None);
        (before.world, next, event, seen)
    };

    let (before, next, event, seen) = step(&[READ_A]);
    assert_eq!(
        event.reply,
        Reply::Refused(StoreError::Stale(Stale::Target))
    );
    assert!(seen.decisions.contains("Client::transfer"));
    assert!(!seen.witnesses.contains(TRANSFER_COMMITTED));
    assert_eq!(event.earlier, None);
    let bump = event.commit.as_ref().expect("A's bump committed");
    assert_eq!(
        (bump.pending.kind, bump.written.owner, bump.written.attempts),
        (Kind::Bump, Side::A.host(), 2)
    );
    assert_eq!(next.handed(), None);
    assert_eq!(next.mints().len(), before.mints().len() + 1);

    let named = [Action::ReconcilerRead, Action::Designate(Arm::Pass), READ_A];
    let (_, next, event, seen) = step(&named);
    assert_eq!(event.reply, Reply::Done);
    assert!(seen.decisions.contains("Client::transfer"));
    assert!(seen.witnesses.contains(TRANSFER_COMMITTED));
    let bump = event.earlier.as_ref().expect("A's bump committed first");
    assert_eq!(bump.pending.kind, Kind::Bump);
    let transfer = event.commit.as_ref().expect("the transfer committed");
    assert_eq!(transfer.pending.kind, Kind::Transfer);
    assert_eq!(transfer.below, bump.written);
    assert_eq!(
        (transfer.written.owner, transfer.written.attempts),
        (Side::C.host(), bump.written.attempts + 1)
    );
    assert_eq!(next.handed(), Some(Target::of(&transfer.written)));
}

/// A transfer spends the world's one transfer only when its request reaches the store. At top 3, where A's reread at
/// `E = 2` is owned, below the top and leaves room for both writes, a transfer refused before its request leaves
/// A's next transfer enabled, as a plain bump does; after a committed transfer and A's takeover back at `E = 4` under
/// top 5, A's read is owned, below the top and fits the budget, and the spent transfer alone disables the next one.
#[test]
fn a_transfer_spends_the_budget_only_when_its_request_reaches_the_store() {
    let at_top = |top, designations| Records {
        bound: Bound {
            top,
            designations,
            ..TRANSFER_BOUND
        },
        ..Records::new(Plant::None)
    };
    let records = at_top(3, 1);
    for path in [[READ_A, TRANSFER_A, READ_A], [READ_A, BUMP_A, READ_A]] {
        let reread = replay(&records, &path);
        assert_eq!(reread.end, End::Applied, "{path:?}");
        assert_eq!(reread.world.record().attempts, 2, "{path:?}");
        assert!(records.enabled(&reread.world, TRANSFER_A), "{path:?}");
    }

    let records = at_top(5, 2);
    let path = [
        TRANSFER_KEEPS_E.as_slice(),
        &[
            Action::ReconcilerRead,
            Action::Designate(Arm::Pass),
            READ_A,
            Action::TakeOver(Side::A, Arm::Pass),
            READ_A,
        ],
    ]
    .concat();
    let spent = replay(&records, &path);
    assert_eq!(spent.end, End::Applied);
    let record = *spent.world.record();
    assert_eq!((record.owner, record.attempts), (Side::A.host(), 4));
    assert!(records.enabled(&spent.world, BUMP_A));
    assert!(!records.enabled(&spent.world, TRANSFER_A));
}

/// The transfer step's bump earns the witnesses of a host's acknowledged bump: after A's bump whose reply was lost
/// while it committed, A's reread and transfer, stepped with a fresh `Seen` at a bound with one fault, record the
/// bump after a lost commit even though the transfer refuses.
#[test]
fn the_transfer_s_bump_earns_the_acknowledged_bump_witnesses() {
    let records = Records {
        bound: Bound {
            top: 3,
            faults: 1,
            ..TRANSFER_BOUND
        },
        ..Records::new(Plant::None)
    };
    let lost = Action::Bump(Side::A, Arm::Timeout { commit: true });
    let reread = replay(&records, &[READ_A, lost, READ_A]);
    assert_eq!(reread.end, End::Applied);
    assert!(records.enabled(&reread.world, TRANSFER_A));
    let mut seen = Seen::default();
    let (_, event) = records
        .step(&reread.world, TRANSFER_A, &mut seen)
        .expect("the transfer step applies");
    assert_eq!(
        event.reply,
        Reply::Refused(StoreError::Stale(Stale::Target))
    );
    let bump = event.commit.expect("A's bump committed");
    assert_eq!((bump.below.attempts, bump.written.attempts), (2, 3));
    assert!(seen.witnesses.contains(BUMP_AFTER_LOST_COMMIT));
}

/// The transfer step's two writes fit the budget: with top 2 and no handoff, A's read at `E = 1` leaves no room for
/// the transfer's write at `E = 3`, so the transfer is disabled while A's bump stays enabled; with top 3 both writes
/// fit and the transfer is enabled.
#[test]
fn a_transfer_is_enabled_only_where_both_its_writes_fit_the_budget() {
    for (top, enabled) in [(2, false), (3, true)] {
        let records = Records {
            bound: Bound {
                top,
                handoff: 0,
                ..TRANSFER_BOUND
            },
            ..Records::new(Plant::None)
        };
        let read = replay(&records, &[READ_A]).world;
        assert!(records.enabled(&read, BUMP_A), "top {top}");
        assert_eq!(records.enabled(&read, TRANSFER_A), enabled, "top {top}");
    }
}

/// The handoff's budget belongs to the tenure the transfer wrote: after the transfer to C at `E = 3`, A's takeover at
/// `E = 4` and C's takeover back at `E = 5`, C holds the record at the top of a bound with top 5, and its bump above
/// the top stays disabled.
#[test]
fn a_later_tenure_of_the_target_takes_no_handoff_budget() {
    let records = Records {
        bound: Bound {
            top: 5,
            designations: 3,
            ..TRANSFER_BOUND
        },
        ..Records::new(Plant::None)
    };
    let path = [
        TRANSFER_KEEPS_E.as_slice(),
        &[
            Action::ReconcilerRead,
            Action::Designate(Arm::Pass),
            READ_A,
            Action::TakeOver(Side::A, Arm::Pass),
            Action::ReconcilerRead,
            Action::Designate(Arm::Pass),
            READ_C,
            TAKEOVER_C,
            READ_C,
        ],
    ]
    .concat();
    let replayed = replay(&records, &path);
    assert_eq!(replayed.end, End::Applied);
    let record = *replayed.world.record();
    assert_eq!((record.owner, record.attempts), (Side::C.host(), 5));
    let handed = Target {
        attempts: 3,
        ..Target::of(&record)
    };
    assert_eq!(replayed.world.handed(), Some(handed));
    assert!(!records.enabled(&replayed.world, Action::Bump(Side::C, Arm::Pass)));

    let wider = Records {
        bound: Bound {
            top: 6,
            ..records.bound
        },
        ..Records::new(Plant::None)
    };
    let replayed = replay(&wider, &path);
    assert_eq!(replayed.end, End::Applied);
    let bump_c = Action::Bump(Side::C, Arm::Pass);
    assert!(wider.enabled(&replayed.world, bump_c));
    let mut seen = Seen::default();
    let (next, event) = wider
        .step(&replayed.world, bump_c, &mut seen)
        .expect("C's ordinary bump applies");
    assert_eq!(event.reply, Reply::Done);
    let commit = event.commit.expect("C's bump committed");
    assert_eq!(commit.written.attempts, 6);
    assert!(!seen.witnesses.contains(TARGET_BUMP_AFTER_TRANSFER));
    assert_eq!(next.handed(), Some(handed));
}

/// The handed tenure comes from the transfer's input: under the `transfer-keeps-e` plant the store holds C at the
/// bump's `E = 2` while the handed tenure names C at `E = 3`, so C's read of the written record leaves its bump above
/// the top disabled.
#[test]
fn the_handed_tenure_follows_the_transfer_s_input_not_its_written_value() {
    let planted = transfer_records(Plant::TransferKeepsE);
    let broken = replay(&planted, &TRANSFER_KEEPS_E);
    assert_eq!(
        broken.end,
        End::Violation {
            property: "NamedStandbyTakesOver",
            path: TRANSFER_KEEPS_E.to_vec()
        }
    );
    let written = *broken.world.record();
    assert_eq!((written.owner, written.attempts), (Side::C.host(), 2));
    let intended = Target {
        attempts: 3,
        ..Target::of(&written)
    };
    assert_eq!(broken.world.handed(), Some(intended));
    let (read, _) = planted
        .step(&broken.world, READ_C, &mut Seen::default())
        .expect("C reads the written record");
    assert!(!planted.enabled(&read, Action::Bump(Side::C, Arm::Pass)));
}
