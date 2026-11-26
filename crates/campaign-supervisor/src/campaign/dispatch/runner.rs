use crate::campaign::triage;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use super::{Error, Options, Report, State, name, policy, recovery::Jobs};
use crate::attempt::{self, Attempt, Completed, Launch};
use crate::custody::{Custody, Limits, Running};
use crate::record::Configuration;
use crate::store::Store;

struct Dispatcher<'a> {
    store: &'a Store,
    custody: &'a mut Custody,
    options: &'a Options,
    config: Configuration,
    limits: Limits,
    build: crate::record::Digest,
    jobs: Jobs,
    attempts: BTreeMap<String, Attempt>,
    running: Vec<Running>,
    steps: BTreeMap<String, triage::Step>,
    unchanged: BTreeSet<String>,
    pending: Vec<(String, Completed, bool)>,
    /// The session's failure pins without a resolved disposition: counted
    /// at the first start decision, then raised by each pin the session
    /// writes. The lock makes this controller the only writer of pins and
    /// dispositions.
    backlog: Option<u64>,
    /// The backlog hold that ended ordinary admission. The count only
    /// rises within a session, so the hold stands until the window ends.
    /// Triage steps write no failure pin, so triage admission continues;
    /// `run` refuses with this hold once the window drains.
    backlog_hold: Option<Error>,
    /// The session's census: counted before the first start decision, then
    /// charged with each attempt that leaves the running set, at its job's
    /// fork shares, and each record the session publishes in `jobs/`. The
    /// lock makes this controller the only writer, so the count matches a
    /// fresh census until a settlement or conclusion error, or an attempt
    /// listing at the scan bound, which stops the session's admission. A pass
    /// with deletions or a new reclaim marker invalidates the count before
    /// the next storage decision.
    census: Option<crate::campaign::census::Census>,
    /// This loop iteration's collect pass, `None` before the iteration
    /// runs one.
    collected: Option<Collected>,
    /// The deletion budget for the next collect pass.
    budget: usize,
    report: Report,
}

/// The deletion budget of the first collect pass in a run of consecutive
/// dispatch-owned passes. Each probe directory counts as one deletion
/// against the budget. Each pass's budget bounds its deletions; its
/// snapshot and plan read the whole store, so duration depends on store size.
pub(in crate::campaign) const PASS_DELETIONS: usize = 256;

/// The outcome of a loop iteration's collect pass.
struct Collected {
    changed: bool,
    /// The sweep and attempt plan completed; a gating hold leaves this false.
    finished: bool,
    /// The first remaining collection diagnostic.
    held: Option<String>,
}

/// The storage dimensions a collect pass can lower.
fn storage(dimension: &str) -> bool {
    matches!(
        dimension,
        "artifact_bytes" | "artifact_inodes" | "disk" | "disk_inodes"
    )
}

/// An idle completed pass that changed nothing holds on artifact limits.
/// Its first remaining diagnostic identifies evidence to inspect.
fn exhausted(
    collected: Option<&Collected>,
    paused: &BTreeSet<String>,
    idle: bool,
) -> Result<(), Error> {
    let operator = paused
        .iter()
        .filter(|dimension| matches!(dimension.as_str(), "artifact_bytes" | "artifact_inodes"))
        .cloned()
        .collect::<Vec<_>>();
    if let Some(Collected {
        changed: false,
        finished: true,
        held,
    }) = collected
        && idle
        && !operator.is_empty()
    {
        let mut reason = format!(
            "{} exhausted and collect reclaims nothing; raise it with configure",
            operator.join(" and ")
        );
        if let Some(held) = held {
            reason.push_str(&format!(
                "; collection kept {held}; inspect the held evidence"
            ));
        }
        return Err(Error::Held(reason));
    }
    Ok(())
}

fn collecting_stops(
    signal: Result<Option<i32>, crate::custody::Error>,
    deadline: Option<Instant>,
    fault: &mut Option<crate::custody::Error>,
) -> bool {
    let signalled = match signal {
        Ok(signal) => signal.is_some(),
        Err(error) => {
            fault.get_or_insert(error);
            true
        }
    };
    signalled || deadline.is_some_and(|deadline| Instant::now() >= deadline)
}

pub fn dispatch(store: &Store, custody: &mut Custody, options: &Options) -> Result<Report, Error> {
    let (mut report, _) = session(store, custody, options)?;
    report.finish(store);
    Ok(report)
}

/// Runs one session, returning its report and the census it ended with,
/// `None` when no decision counted one.
pub(in crate::campaign) fn session(
    store: &Store,
    custody: &mut Custody,
    options: &Options,
) -> Result<(Report, Option<crate::campaign::census::Census>), Error> {
    crate::sys::controller_file_limit().map_err(crate::store::Error::Io)?;
    let mut report = Report::default();
    match crate::campaign::calibration::reconcile(store, custody) {
        Ok(held) => report.calibration_held = held,
        Err(error) => {
            report.error(error);
            return Ok((report, None));
        }
    }
    let mut census = None;
    match triage::reconcile_counted(store, custody, &mut census) {
        Ok(skipped) => report.triage_skipped = skipped,
        Err(error) => report.error(error),
    }
    if let Err(error) = crate::campaign::probe::reconcile_records(store, custody) {
        report.error(error);
    }
    let loaded = match Jobs::load(store, &mut report) {
        Ok(loaded) => loaded,
        Err(error) => {
            report.error(error);
            return Ok((report, None));
        }
    };
    let Some(mut jobs) = loaded else {
        match custody.unrecorded(&[], crate::scan_bound()) {
            Ok(groups) if groups.is_empty() => {}
            Ok(_) => report.refuse("cgroup without job record".into()),
            Err(error) => report.refuse(error.to_string()),
        }
        return Ok((report, None));
    };
    jobs.reconcile(store, custody, &mut report, &mut census);
    if !report.refusals.is_empty() {
        return Ok((report, None));
    }
    let setup = (|| -> Result<_, Error> {
        let config = store
            .read_record::<Configuration>(store.root(), &name("config.json"))?
            .ok_or_else(|| Error::Held("dispatch configuration missing".into()))?;
        store.barrier(config.read())?;
        let archive = crate::archive::Archive::load(&options.archive).map_err(|error| {
            if error.exit(false) == crate::exit::Sim::Rejected {
                Error::Rejected(error.to_string())
            } else {
                Error::Held(error.to_string())
            }
        })?;
        custody.set_release_deadline(options.deadline);
        custody.set_watchdog(config.record().value("wall"))?;
        let limits = crate::campaign::configuration::limits(config.record());
        limits.validate().map_err(Error::custody)?;
        policy::ancestor_fit(custody, limits, config.record())?;
        Ok((config.record().clone(), limits, archive.id()))
    })();
    let (config, limits, build) = match setup {
        Ok(setup) => setup,
        Err(error) => {
            report.error(error);
            return Ok((report, None));
        }
    };
    // Admission copies the complete reconciliation skip set before sampling.
    let unchanged = report.triage_skipped.keys().cloned().collect();
    report.trim_diagnostics();
    Dispatcher {
        store,
        custody,
        options,
        config,
        limits,
        build,
        jobs,
        attempts: BTreeMap::new(),
        running: Vec::new(),
        steps: BTreeMap::new(),
        unchanged,
        pending: Vec::new(),
        backlog: None,
        backlog_hold: None,
        census,
        collected: None,
        budget: PASS_DELETIONS,
        report,
    }
    .run()
}

impl Dispatcher<'_> {
    fn run(mut self) -> Result<(Report, Option<crate::campaign::census::Census>), Error> {
        loop {
            self.collected = None;
            if let Err(error) = self.admit_ordinary() {
                self.report.error(error);
            }
            if !self.report.stopping()
                && let Err(error) = self.admit_triage()
            {
                self.report.error(error);
            }
            self.report.trim_diagnostics();
            if self.running.is_empty()
                && !self.report.stopping()
                && self.report.state == State::Paused
                && self.collected.as_ref().is_some_and(|pass| pass.changed)
            {
                // The pass changed storage but left a pause; the
                // next iteration runs another pass before the window ends.
                self.budget = self.budget.saturating_mul(2);
                continue;
            }
            self.budget = PASS_DELETIONS;
            if self.running.is_empty() {
                // Triage admission can end on an interruption or the
                // deadline after ordinary admission named its state.
                match self.stop() {
                    Ok(Some(state)) => self.report.state = state,
                    Ok(None) => {}
                    Err(error) => self.report.error(error),
                }
                break;
            }
            let waited = match self.custody.wait_any(std::mem::take(&mut self.running)) {
                Ok(waited) => waited,
                Err(error) => {
                    self.report.refuse(error.to_string());
                    let mut retained = self.custody.take_retained();
                    for (id, attempt) in std::mem::take(&mut self.attempts) {
                        if self.custody.held_identity() == Some(attempt.identity())
                            || self.custody.resource_faulted(attempt.identity())
                        {
                            continue;
                        }
                        let observed = retained
                            .iter()
                            .position(|running| {
                                running.started().record().attempt == *attempt.identity()
                            })
                            .map(|index| retained.swap_remove(index));
                        let completed = match observed {
                            Some(running) => self.custody.stop(running).and_then(|stopped| {
                                attempt.finish(self.store, stopped, attempt::EVIDENCE_BOUND)
                            }),
                            None => {
                                attempt.reconcile(self.store, self.custody, attempt::EVIDENCE_BOUND)
                            }
                        };
                        self.conclude(id, completed);
                    }
                    for (id, step) in std::mem::take(&mut self.steps) {
                        if self.custody.held_identity() == Some(step.identity())
                            || self.custody.resource_faulted(step.identity())
                        {
                            continue;
                        }
                        let observed = retained
                            .iter()
                            .position(|running| {
                                running.started().record().attempt == *step.identity()
                            })
                            .map(|index| retained.swap_remove(index));
                        let result = match observed {
                            Some(running) => self
                                .custody
                                .stop(running)
                                .map_err(Error::custody)
                                .and_then(|stopped| step.finish(self.store, stopped)),
                            None => step.reconcile(self.store, self.custody),
                        };
                        match result {
                            Ok(result) => self.report.triage(result),
                            Err(error) => self.triage_error(id, error),
                        }
                    }
                    break;
                }
            };
            self.running = waited.to_drain;
            if let Some(id) = self
                .steps
                .iter()
                .find(|(_, step)| step.identity() == waited.stopped.identity())
                .map(|(id, _)| id.clone())
            {
                let step = self
                    .steps
                    .remove(&id)
                    .expect("stopped triage identity was found");
                match step.finish(self.store, waited.stopped) {
                    Ok(result) => {
                        if result.status.is_none() {
                            self.unchanged.insert(id);
                        }
                        self.report.triage(result);
                    }
                    Err(error) => self.triage_error(id, error),
                }
                continue;
            }
            let id = self
                .attempts
                .iter()
                .find(|(_, attempt)| attempt.identity() == waited.stopped.identity())
                .map(|(id, _)| id.clone())
                .ok_or_else(|| Error::Held("custody returned unknown attempt".into()))?;
            let attempt = self
                .attempts
                .remove(&id)
                .expect("stopped identity was found");
            let completed = attempt.finish(self.store, waited.stopped, attempt::EVIDENCE_BOUND);
            self.conclude(id, completed);
        }
        self.settle_pending();
        if let Some(hold) = self.backlog_hold.take() {
            self.report.error(hold);
        }
        Ok((self.report, self.census))
    }

    fn admit_ordinary(&mut self) -> Result<(), Error> {
        self.settle_pending();
        if self.pending.is_empty() {
            self.report.state = self.admission()?;
        }
        Ok(())
    }

    fn triage_error(&mut self, id: String, error: Error) {
        self.unchanged.insert(id.clone());
        if matches!(error, Error::Rejected(_)) {
            self.report.error(error);
        } else if triage::global(&error) {
            self.report.refuse(error.to_string());
        } else {
            self.report.triage_skipped.insert(id, error.to_string());
            self.report.trim_diagnostics();
        }
    }

    fn fit(&mut self) -> Result<(), Error> {
        policy::fit_or_stop(
            self.custody,
            self.limits,
            &self.config,
            &mut self.running,
            self.steps.len(),
        )
    }

    /// A completion whose capture waits for the running set to drain pauses
    /// triage admission.
    fn admit_triage(&mut self) -> Result<(), Error> {
        while !self.report.stopping()
            && self.pending.is_empty()
            && (self.steps.len() as u64) < self.config.value("reserve_slots")
            && self.custody.interruption()?.is_none()
            && self
                .options
                .deadline
                .is_none_or(|deadline| Instant::now() < deadline)
        {
            self.fit()?;
            let mut skip = self.unchanged.clone();
            skip.extend(self.steps.keys().cloned());
            let selected = triage::select(self.store, self.build, &self.config, &skip)?;
            self.unchanged.extend(selected.skipped.keys().cloned());
            self.unchanged.extend(selected.ineligible);
            self.report.triage_skipped.extend(selected.skipped);
            self.report.trim_diagnostics();
            let Some((id, kind)) = selected.next else {
                break;
            };
            let output = self
                .attempts
                .iter()
                .fold(0u64, |sum, (id, attempt)| {
                    sum.saturating_add(
                        attempt
                            .output()
                            .saturating_mul(self.jobs.records[id].shares()),
                    )
                })
                .saturating_add((self.steps.len() as u64).saturating_mul(self.config.file_bytes()));
            let launch = Launch {
                gate: self.options.gate.clone(),
                launcher: self.options.launcher.clone(),
                environment: self.options.environment.clone(),
                limits: self.limits,
            };
            debug_assert!(self.census.is_some() || self.attempts.is_empty());
            let admission = match triage::admit(
                self.store,
                self.custody,
                triage::Request {
                    id: &id,
                    kind,
                    archive: Some(&self.options.archive),
                },
                &self.config,
                launch,
                triage::Occupancy {
                    census: &mut self.census,
                    steps: self.steps.len(),
                    committed_output: output,
                    running: &mut self.running,
                },
            ) {
                Ok(admission) => admission,
                Err(error) => {
                    self.triage_error(id, error);
                    continue;
                }
            };
            let (step, mut process) = match admission {
                triage::Admission::Started(pair) => *pair,
                triage::Admission::Drain(result) => {
                    if let Some(result) = result {
                        self.report.triage(*result);
                    }
                    break;
                }
                triage::Admission::Pause(reasons) => {
                    if self.running.is_empty()
                        && self.collected.is_none()
                        && reasons.iter().any(|reason| storage(reason))
                    {
                        self.collect_pass()?;
                        continue;
                    }
                    if self.custody.interruption()?.is_some()
                        || self
                            .options
                            .deadline
                            .is_some_and(|deadline| Instant::now() >= deadline)
                    {
                        break;
                    }
                    exhausted(self.collected.as_ref(), &reasons, self.running.is_empty())?;
                    self.report.pause(reasons);
                    if matches!(
                        self.report.state,
                        State::QueueEmpty | State::MaxAttempts | State::Held
                    ) {
                        self.report.state = State::Paused;
                    }
                    break;
                }
                triage::Admission::Skip(reason) => {
                    self.unchanged.insert(id.clone());
                    self.report.triage_skipped.insert(id, reason);
                    self.report.trim_diagnostics();
                    continue;
                }
            };
            if let Some(deadline) = self.options.deadline {
                process.stop_at(deadline);
            }
            self.steps.insert(id, step);
            self.running.push(process);
            self.report.triage_started += 1;
        }
        Ok(())
    }

    /// The session census, counted on first use. Every start follows a
    /// storage decision that reads the census, so the first use precedes
    /// the first start and the count charges no running attempt. A productive
    /// collect pass invalidates the cached count before the next decision.
    fn census(&mut self) -> Result<crate::campaign::census::Census, Error> {
        debug_assert!(self.census.is_some() || self.attempts.is_empty());
        crate::campaign::census::Census::cached(&mut self.census, self.store)
    }

    /// The storage dimensions that pause a start of `committed` more
    /// shares. When one does and nothing runs, the iteration's collect pass
    /// runs first and the session census is counted again after it. A pass
    /// that a signal or the deadline stops ends the decision with the
    /// dimensions that fired before it, and the census stays uncounted. A
    /// dimension only the operator can lower holds when a finished pass
    /// changed nothing. The hold names the remedy; the measured `disk`
    /// and `disk_inodes` dimensions pause.
    ///
    /// # Errors
    ///
    /// Census and collection errors, except hardware lock contention,
    /// and exhaustion while the window remains open.
    fn storage_pauses(&mut self, committed: u64) -> Result<BTreeSet<String>, Error> {
        let reserve = self.config.value("reserve_slots");
        let usage = self.census()?.usage(self.store, &self.config)?;
        let mut paused = policy::storage_pauses(&self.config, usage, committed, reserve);
        if paused.is_empty() || !self.running.is_empty() {
            return Ok(paused);
        }
        if self.collected.is_none() {
            self.collect_pass()?;
            if self.stop()?.is_some() {
                return Ok(paused);
            }
            let usage = self.census()?.usage(self.store, &self.config)?;
            paused = policy::storage_pauses(&self.config, usage, committed, reserve);
        }
        if self.stop()?.is_none() {
            exhausted(self.collected.as_ref(), &paused, self.running.is_empty())?;
        }
        Ok(paused)
    }

    /// Records the pass outcome in `collected`, invalidating the census
    /// after a deletion or a new reclaim marker. Hardware lock contention
    /// leaves admission paused until a later window can take the snapshot.
    ///
    /// # Errors
    ///
    /// Collection errors other than hardware snapshot lock contention.
    fn collect_pass(&mut self) -> Result<(), Error> {
        let (store, custody) = (self.store, &mut *self.custody);
        let (deadline, budget) = (self.options.deadline, self.budget);
        // The snapshot and plan finish their reads before deletion checks.
        // A signal or deadline stops at the next deletion check; a signal-read
        // fault is retained until the pass outcome and census are recorded.
        self.report.collect_passes += 1;
        self.report.collect_finished = None;
        let mut fault = None;
        let result = crate::campaign::collect::pass(store, false, budget, &mut || {
            collecting_stops(custody.interruption(), deadline, &mut fault)
        });
        let pass = match result {
            Err(Error::Store(crate::store::Error::Busy)) => {
                // The hardware writer owns the snapshot lock. Pausing keeps
                // its subtree intact until collection can acquire the lock.
                self.report.collect_finished = Some(false);
                self.collected = Some(Collected {
                    changed: false,
                    finished: false,
                    held: None,
                });
                return Ok(());
            }
            result => result?,
        };
        self.report.collect_deletions += pass.deletions as u64;
        self.report.collect_finished = Some(pass.finished);
        self.collected = Some(Collected {
            changed: pass.changed,
            finished: pass.finished,
            held: pass.held,
        });
        if pass.changed {
            self.census = None;
        }
        if let Some(error) = fault {
            return Err(error.into());
        }
        Ok(())
    }

    /// Records attempt `number` of job `id` as minted. The session census
    /// holds the way a fresh count would once that attempt fills the job's
    /// attempt listing to the scan bound.
    fn minted(&mut self, id: &str, number: u64) {
        if let Err(error) = crate::campaign::census::minted(id, number) {
            self.report.error(error);
        }
        self.jobs.counts.insert(id.to_owned(), number);
    }

    /// Charges the census with one attempt of job `id` that left the
    /// running set.
    fn charge_concluded(&mut self, id: &str) {
        let shares = self.jobs.records[id].shares();
        if let Some(census) = self.census.as_mut() {
            census.concluded(shares);
        }
    }

    /// Records the conclusion of an attempt that left the running set.
    fn conclude(&mut self, id: String, completed: Result<Completed, crate::custody::Error>) {
        self.charge_concluded(&id);
        match completed {
            Ok(completed) => self.pending.push((id, completed, true)),
            Err(error) => self.report.refuse(format!("job {id}: {error}")),
        }
    }

    fn settle_pending(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let mut capture_ready = self.custody.held_identity().is_none();
        match self.custody.unattended(&self.running, crate::scan_bound()) {
            Ok(groups) if groups.is_empty() => {}
            Ok(_) => {
                capture_ready = false;
                self.report
                    .refuse("attempt cgroup remains before settlement".into());
            }
            Err(error) => {
                capture_ready = false;
                self.report.refuse(error.to_string());
            }
        }
        let mut waiting = Vec::new();
        for (id, completed, emit) in std::mem::take(&mut self.pending) {
            if !capture_ready {
                if emit {
                    self.report.complete(completed.finished().record().clone());
                }
                continue;
            }
            if completed.has_finding() && !self.running.is_empty() {
                waiting.push((id, completed, emit));
                continue;
            }
            match self
                .jobs
                .settle(self.store, &mut self.report, &id, completed, emit)
            {
                Ok(published) => {
                    if let Some(backlog) = self.backlog.as_mut() {
                        *backlog += u64::from(published.pin.is_some());
                    }
                    if let Some(census) = self.census.as_mut() {
                        for bytes in [published.pin, published.result].into_iter().flatten() {
                            if let Err(error) =
                                census.published(crate::layout::shard(&id).as_str(), bytes)
                            {
                                self.report.error(error);
                            }
                        }
                    }
                }
                Err(error) => self.report.error(error.about(format_args!("job {id}"))),
            }
        }
        self.pending = waiting;
    }

    /// The state that stops ordinary admission before its next decision. A
    /// refusal, a rejection or the kept backlog hold returns `Held` here;
    /// [`Report::finish`] names which one stopped the window.
    fn stop(&mut self) -> Result<Option<State>, Error> {
        Ok(if self.report.stopping() || self.backlog_hold.is_some() {
            Some(State::Held)
        } else if self.custody.interruption()?.is_some() {
            Some(State::Interrupted)
        } else if self
            .options
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            Some(State::Deadline)
        } else if self
            .options
            .max_attempts
            .is_some_and(|maximum| self.report.started >= maximum)
        {
            Some(State::MaxAttempts)
        } else {
            None
        })
    }

    /// Starts queued jobs until a decision stops admission, returning the
    /// state that decision names. An error becomes a refusal or a
    /// rejection, and [`Report::finish`] makes that the window's state. The
    /// backlog hold is kept for the end of the window, so it stops job
    /// starts and leaves triage admission running.
    fn admission(&mut self) -> Result<State, Error> {
        loop {
            if let Some(state) = self.stop()? {
                return Ok(state);
            }
            for attempt in self.attempts.values() {
                if !attempt.reservation(self.store)? {
                    return Err(Error::Held("running attempt lacks reservation".into()));
                }
            }
            let queue: Vec<_> = self.jobs.queued().map(|(_, job)| job).collect();
            let (reasons, allowed) = policy::builds(
                &queue,
                !self.running.is_empty(),
                self.build,
                self.config.value("retained_builds"),
            );
            let held_back = !reasons.is_empty();
            if !allowed {
                self.report.pause(reasons.into_iter().map(str::to_owned));
                return Ok(if held_back {
                    State::Paused
                } else {
                    State::QueueEmpty
                });
            }
            self.report
                .paused
                .extend(reasons.into_iter().map(str::to_owned));
            let Some(id) = self.jobs.next(&self.attempts, self.build) else {
                return Ok(State::QueueEmpty);
            };
            let job = self
                .jobs
                .records
                .get(&id)
                .ok_or_else(|| Error::Held("queued job vanished".into()))?;
            let shares = job.shares();
            let reserve = self.config.value("reserve_slots");
            let fits = |units: u64| {
                units <= self.config.value("cores")
                    && u128::from(units) * u128::from(self.config.value("tree_memory"))
                        <= u128::from(self.config.value("memory"))
            };
            if !fits(shares + reserve)
                || u128::from(shares + reserve) * self.config.charge().bytes
                    >= u128::from(self.config.value("artifact_bytes"))
                || u128::from(shares + reserve) * self.config.charge().inodes
                    >= u128::from(self.config.value("artifact_inodes"))
                || attempt::scaled(self.limits, shares).is_err()
            {
                self.report.unfit.insert(
                    id.clone(),
                    "target shares exceed exploration capacity".into(),
                );
                self.jobs.excluded.insert(id);
                continue;
            }
            match self.custody.validate_limits(
                policy::aggregate(
                    self.limits,
                    std::iter::once(attempt::scaled(self.limits, shares)?),
                    reserve,
                    0,
                )?,
                1,
            ) {
                Ok(()) => {}
                Err(crate::store::cgroup::FitError::Limit { .. }) => {
                    self.fit()?;
                    self.report
                        .unfit
                        .insert(id.clone(), "target shares exceed ancestor capacity".into());
                    self.jobs.excluded.insert(id);
                    continue;
                }
                Err(crate::store::cgroup::FitError::Io(error)) => {
                    return Err(Error::Store(crate::store::Error::Io(error)));
                }
            }
            let charged: u64 = self
                .attempts
                .keys()
                .map(|id| self.jobs.records[id].shares())
                .sum();
            if self.attempts.len() as u64 >= self.config.value("slots") {
                self.report.pause(["slots".to_owned()]);
                return Ok(State::Paused);
            }
            let ancestor_fits = match self.custody.validate_limits(
                policy::aggregate(
                    self.limits,
                    self.running
                        .iter()
                        .map(|process| process.limits())
                        .chain(std::iter::once(attempt::scaled(self.limits, shares)?)),
                    reserve.saturating_sub(self.steps.len() as u64),
                    0,
                )?,
                1,
            ) {
                Ok(()) => true,
                Err(crate::store::cgroup::FitError::Limit { .. }) => false,
                Err(crate::store::cgroup::FitError::Io(error)) => {
                    return Err(Error::Store(crate::store::Error::Io(error)));
                }
            };
            if !fits(charged + shares + reserve) || !ancestor_fits {
                self.fit()?;
                self.report.pause(["target_shares".to_owned()]);
                return Ok(State::Paused);
            }
            let backlog = match self.backlog {
                Some(backlog) => backlog,
                None => *self.backlog.insert(policy::backlog(self.store)?),
            };
            if let Err(hold) = policy::backlog_hold(&self.config, backlog) {
                self.backlog_hold = Some(hold);
                return Ok(State::Held);
            }
            let committed = charged + shares - 1;
            let paused = self.storage_pauses(committed)?;
            if !paused.is_empty() {
                self.report.pause(paused);
                return Ok(State::Paused);
            }
            self.fit()?;
            let launch = Launch {
                gate: self.options.gate.clone(),
                launcher: self.options.launcher.clone(),
                environment: self.options.environment.clone(),
                limits: self.limits,
            };
            self.custody.set_watchdog(self.config.value("wall"))?;
            let (attempt, mut process) = match attempt::start(
                self.store,
                self.custody,
                self.jobs.read(self.store, &id)?,
                launch,
            ) {
                Ok(started) => started,
                Err(error) => {
                    if !error.draining() {
                        self.report
                            .error(Error::from(error).about(format_args!("job {id}")));
                    }
                    let before = self.jobs.counts.get(&id).copied();
                    match self.jobs.reconcile_job(self.store, self.custody, &id) {
                        Ok(Some((completed, emit))) => {
                            // A start that failed before minting leaves the
                            // previous attempt, which the census already
                            // charges, as the job's current one.
                            if let Some(number) = self.jobs.counts.get(&id).copied()
                                && Some(number) != before
                            {
                                self.minted(&id, number);
                                self.charge_concluded(&id);
                            }
                            self.pending.push((id.clone(), completed, emit))
                        }
                        Ok(None) => {}
                        Err(error) => self.report.refuse(format!("job {id}: {error}")),
                    }
                    return Ok(self.stop()?.unwrap_or(State::Interrupted));
                }
            };
            if let Some(deadline) = self.options.deadline {
                process.stop_at(deadline);
            }
            self.minted(&id, attempt.number());
            self.attempts.insert(id, attempt);
            self.running.push(process);
            self.report.started += 1;
        }
    }
}

#[cfg(test)]
#[path = "runner_tests.rs"]
mod tests;
#[cfg(test)]
pub(in crate::campaign) use tests::{
    ordinary_admission_during_triage, resume_pending_capture, run_with_settled,
    triage_admission_waits_for_pending_capture,
};
