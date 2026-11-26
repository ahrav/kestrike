//! A fresh run whose `E` bump has an unknown outcome retains its refusal.
//!
//! `Fresh::run` over a store whose `E` bump returns `StoreError::Unknown`,
//! once with the bump committed and once not, returns
//! `Check::Bump(StoreError::Unknown)` with the flip naming the read
//! `(g, owner, E)`, issues no device command, and calls
//! `LocalRecords::retain_refusal` for the persisted record before it
//! returns. `Refused::retirement` of that refusal is admitted at the read
//! target and at `E + 1`. With a `retain_refusal` that fails, the refusal
//! is `Check::Retention` over the bump refusal with the same flip, and its
//! request is admitted at the exact target only.

use super::admission::AdmissionError;
use super::fresh::tests::{
    Card, Log, Records, fresh_of, holder, plane, records, shard_record, store, volume_record,
};
use super::fresh::{Check, LocalRecords, Refusals, Refused};
use super::poll::Holder;
use super::record::LocalRecord;
use super::records::ShardRecord;
use super::restart::{Local, LocalSource};
use super::retire::{Admitted, Stale, Target};
use crate::storage::store::sim::{Arm, Shared};
use crate::storage::store::{Key, StoreError};
use crate::storage::store_tests::{client, shard};

/// A [`LocalRecords`] double over the baseline's [`Records`]. It passes every call on and keeps, for each
/// retention, the record it was handed and the command log's length at the call, so a test reads which record
/// was retained and where in the sequence. With `retention_fails`, a retention returns `DurableWrite` and
/// leaves the local record in place, the trait's outcome for an exclusion and a removal that both fail.
struct Recording {
    inner: Records,
    log: Log,
    persisted: Option<LocalRecord>,
    retained: Vec<(LocalRecord, usize)>,
    released: usize,
    retention_fails: bool,
}

impl Recording {
    fn new(log: &Log, retention_fails: bool) -> Self {
        Self {
            inner: records(log),
            log: log.clone(),
            persisted: None,
            retained: Vec::new(),
            released: 0,
            retention_fails,
        }
    }
}

impl LocalRecords for Recording {
    fn persist(
        &mut self,
        holder: &Holder,
        attempt: u32,
        key: super::identity::Key,
    ) -> Result<LocalRecord, AdmissionError> {
        let record = self.inner.persist(holder, attempt, key)?;
        self.persisted = Some(record.clone());
        Ok(record)
    }

    fn retain_refusal(&mut self, record: &LocalRecord) -> Result<(), AdmissionError> {
        self.retained
            .push((record.clone(), self.log.borrow().len()));
        if self.retention_fails {
            return Err(AdmissionError::DurableWrite);
        }
        self.inner.retain_refusal(record)
    }

    fn release_refusal(&mut self, record: &LocalRecord) -> Result<(), AdmissionError> {
        self.released += 1;
        self.inner.release_refusal(record)
    }
}

/// What one fresh run left, read after [`Fresh::run`](super::fresh::Fresh::run) returned and before any other
/// call on the local records.
struct Outcome {
    /// The refusal, or `None` when the run activated.
    refused: Option<Refused>,
    refusals: Refusals,
    /// The command log: the local record's write and each device command, in order.
    log: Vec<&'static str>,
    persisted: Option<LocalRecord>,
    retained: Vec<(LocalRecord, usize)>,
    released: usize,
    /// What a later fresh start's `persist` of the same attachment returns.
    rerun: Result<LocalRecord, AdmissionError>,
    /// What a later restart's local-record read returns.
    restart: Result<LocalRecord, Local>,
    /// The stored shard record after the run.
    stored: ShardRecord,
}

/// Runs the fresh path once over a store seeded at `E = 0` whose fourth request, the bump, takes `bump`; the
/// record reads and the enrollment write before it pass.
fn run(bump: Arm, retention_fails: bool) -> Outcome {
    let store: Shared = store(shard_record(0), volume_record());
    for arm in [Arm::Pass, Arm::Pass, Arm::Pass, bump] {
        store.schedule(arm);
    }
    let log = Log::default();
    let mut card = Card::new(&log);
    let mut local = Recording::new(&log, retention_fails);
    let mut refusals = Refusals::default();
    let refused = fresh_of(shard(), holder())
        .run(
            &mut client(&store),
            &mut plane(),
            &mut local,
            &mut card,
            &mut refusals,
        )
        .err();
    let (persisted, retained, released) = (
        local.persisted.clone(),
        local.retained.clone(),
        local.released,
    );
    let log = log.borrow().clone();
    let restart = local.inner.local();
    let rerun = local.persist(&holder(), 0, super::records::attachment_key(0).unwrap());
    let stored = *client(&store)
        .read::<ShardRecord>(Key::Shard(shard()))
        .expect("the store answers a read after the run")
        .value();
    Outcome {
        refused,
        refusals,
        log,
        persisted,
        retained,
        released,
        rerun,
        restart,
        stored,
    }
}

/// The read `(g, owner, E)`: the seeded record's target at `E = 0`.
fn read_target() -> Target {
    Target::of(&shard_record(0))
}

/// A bump whose outcome is unknown, committed or not, refuses `Check::Bump(Unknown)` with the flip
/// naming the read `(g, owner, E)` and no device command, and `retain_refusal` has run for the persisted record
/// by the time `run` returns: the double saw one retention of that record, a later fresh `persist` refuses
/// `Retained` and a later restart reads `Local::Retained`. The request is recovering, so it is admitted at the
/// read target and at `E + 1`, whichever record the bump left, and at no later `E`.
#[test]
fn an_unknown_bump_retains_the_persisted_records_refusal_before_run_returns() {
    for commit in [false, true] {
        let outcome = run(Arm::Timeout { commit }, false);
        assert_eq!(
            outcome.stored,
            shard_record(u32::from(commit)),
            "commit {commit}: premise: the arm commits the bump exactly when it says so"
        );
        let refused = outcome
            .refused
            .unwrap_or_else(|| panic!("commit {commit}: an unknown bump refuses"));
        assert_eq!(
            (refused.check.clone(), refused.flip),
            (Check::Bump(StoreError::Unknown), Some(read_target())),
            "commit {commit}"
        );
        assert_eq!(
            outcome.log,
            ["record"],
            "commit {commit}: no device command"
        );
        let persisted = outcome
            .persisted
            .unwrap_or_else(|| panic!("commit {commit}: the local record was persisted"));
        assert_eq!(
            outcome.retained,
            [(persisted, 1)],
            "commit {commit}: one retention, of the persisted record, before run returned"
        );
        assert_eq!(outcome.released, 0, "commit {commit}: the retention stays");
        assert_eq!(
            (outcome.rerun, outcome.restart),
            (Err(AdmissionError::Retained), Err(Local::Retained)),
            "commit {commit}: later fresh and restart starts refuse at the local-record step"
        );
        assert_eq!(
            (
                outcome.refusals.before_commands,
                outcome.refusals.flip_requests,
                outcome.refusals.last.clone()
            ),
            (1, 1, Some(Check::Bump(StoreError::Unknown))),
            "commit {commit}"
        );
        let request = refused
            .retirement(holder().volume)
            .unwrap_or_else(|| panic!("commit {commit}: the refusal requests a retirement"));
        assert_eq!(
            [
                request.admit(&shard_record(0)),
                request.admit(&shard_record(1)),
                request.admit(&outcome.stored),
                request.admit(&shard_record(2)),
            ],
            [
                Ok(Admitted::Flip),
                Ok(Admitted::Flip),
                Ok(Admitted::Flip),
                Err(Stale::Target)
            ],
            "commit {commit}: admitted at the read target and at E + 1 only"
        );
    }
}

/// The retention after an unknown bump is attempted even when it fails, and the failure is reported:
/// the refusal is `Check::Retention` over the bump refusal with the same flip, counted in the bump's phase.
/// Its request is not recovering, so it is admitted at the exact read target and refused at `E + 1`.
#[test]
fn a_failed_retention_after_an_unknown_bump_is_reported_over_the_bump_refusal() {
    for commit in [false, true] {
        let outcome = run(Arm::Timeout { commit }, true);
        let refused = outcome
            .refused
            .unwrap_or_else(|| panic!("commit {commit}: an unknown bump refuses"));
        let retention = Check::Retention {
            original: Box::new(Check::Bump(StoreError::Unknown)),
            error: AdmissionError::DurableWrite,
        };
        assert_eq!(
            (refused.check.clone(), refused.flip),
            (retention.clone(), Some(read_target())),
            "commit {commit}"
        );
        assert_eq!(
            outcome.log,
            ["record"],
            "commit {commit}: no device command"
        );
        let persisted = outcome
            .persisted
            .unwrap_or_else(|| panic!("commit {commit}: the local record was persisted"));
        assert_eq!(
            outcome.retained,
            [(persisted, 1)],
            "commit {commit}: the retention was attempted once, for the persisted record"
        );
        assert_eq!(
            (
                outcome.refusals.before_commands,
                outcome.refusals.flip_requests,
                outcome.refusals.last.clone()
            ),
            (1, 1, Some(retention)),
            "commit {commit}"
        );
        let request = refused
            .retirement(holder().volume)
            .unwrap_or_else(|| panic!("commit {commit}: the refusal requests a retirement"));
        assert_eq!(
            [
                request.admit(&shard_record(0)),
                request.admit(&shard_record(1))
            ],
            [Ok(Admitted::Flip), Err(Stale::Target)],
            "commit {commit}: admitted at the exact target only"
        );
    }
}

/// The same run with an acknowledged bump: nothing is retained at the bump. The one retention is the one that
/// follows the fresh Report and precedes the activation write, the activation releases it, and a later restart
/// reads the local record.
#[test]
fn an_acknowledged_bump_retains_only_after_the_fresh_report_and_activation_releases_it() {
    let outcome = run(Arm::Pass, false);
    assert_eq!(
        outcome.refused, None,
        "an acknowledged bump activates the tenure"
    );
    assert_eq!(outcome.stored, shard_record(1), "the bump committed E = 1");
    let persisted = outcome.persisted.expect("the local record was persisted");
    let report = outcome
        .log
        .iter()
        .position(|&command| command == "report")
        .expect("the run issued the fresh Report");
    assert_eq!(
        outcome.retained,
        [(persisted.clone(), report + 1)],
        "one retention, right after the fresh Report"
    );
    assert_eq!(
        outcome.log.get(report + 1),
        Some(&"write"),
        "the activation write follows the retention"
    );
    assert_eq!(outcome.released, 1, "activation releases the retention");
    assert_eq!(outcome.restart, Ok(persisted));
    assert_eq!(outcome.refusals, Refusals::default());
}
