//! The long-run gate's storage phases. The churn runs on one engine for
//! the gate's action count with every per-action oracle of [`Churn::check`]
//! and every no-allocation window active, then recovers from behind a held
//! reader, judges a funded recovery through the oracle and its
//! continuation and runs its terminal faults on that same engine, through
//! the one sequence [`run_on`] gives every churn. The lifecycle phase
//! keeps its own storages, since it fails an initialization and attaches a
//! fresh storage over another storage's device bytes, and the
//! poisoned-gate phase keeps its own, since a poisoned root gate refuses
//! the maintenance call the terminal close runs through and a closed
//! storage never reaches the gate. Every witness those phases fire joins
//! one require-all set.
//!
//! A probe samples the gate's [`Marks`] from every churn: the device's
//! command records and store growth after each action, after the recovery,
//! after the terminal faults and once each lifecycle and poisoned-gate
//! churn finished, and the live lease credits at each of those points
//! where the storage still reports them. The unreturned credits are read
//! once the recovery released every holder, and the frontier from the
//! continuation over the funded recovery's rows.

use crate::net::world_tests::long_run::continued;
use crate::oracle::{Obligation, Recorder, check};
use crate::sim::long_run_tests::{
    DEVICE_COMMANDS, DEVICE_GROWTH, Gate, LEASE_CREDITS, MANIFEST, Marks, UNRETURNED_CREDITS,
};

use super::super::ExtentLease;
use super::super::lookup_tests::lookup;
use super::super::test_platform::TestPlatform;
use super::{
    Churn, Geometry, Probe, Situation, Witnesses, lifecycle_faults, poisoned_gate, run_on,
    turnovers,
};

/// The storage phases' inputs, from the gate's manifest.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ChurnPlan {
    pub(crate) seed: u64,
    /// Keys route through one-fingerprint groups.
    pub(crate) collide: bool,
    pub(crate) actions: usize,
    /// One extent lease is taken at or after the churn's midpoint and held
    /// through the unreturned-credit check.
    pub(crate) leaked_lease: bool,
}

/// The credits backing live leases of `churn`'s storage, while it reports
/// them.
fn credits(churn: &Churn) -> Option<u64> {
    let report = churn.storage.lease_report()?;
    Some(report.reserved as u64)
}

/// Samples the gate's marks from every churn of the storage phases and
/// makes the gate's checks at the recovery.
struct Sampler<'m> {
    marks: &'m mut Marks,
    plan: ChurnPlan,
    leaked: Option<ExtentLease<'static, TestPlatform>>,
}

impl Sampler<'_> {
    /// Raises the marks to what `churn`'s device and storage hold now.
    fn sample(&mut self, churn: &Churn) {
        let footprint = churn.dev.control.footprint();
        self.marks.sample(DEVICE_COMMANDS, footprint.device as u64);
        self.marks
            .sample(DEVICE_GROWTH, churn.device_growth() as u64);
        if let Some(credits) = credits(churn) {
            self.marks.sample(LEASE_CREDITS, credits);
        }
    }
}

impl Probe for Sampler<'_> {
    fn stepped(&mut self, churn: &mut Churn, at: usize) {
        self.sample(churn);
        if self.plan.leaked_lease
            && self.leaked.is_none()
            && at >= self.plan.actions / 2
            && let Some(key) = churn.pick_object()
        {
            self.leaked = lookup(&mut churn.reader, &key, 4).ok();
        }
    }

    // The recovery starts behind a held reader, so it removes a blocker
    // whatever the last action left.
    fn recovering(&mut self, churn: &mut Churn) {
        if churn.held.is_empty()
            && churn.pinned.is_none()
            && let Some(key) = churn.pick_object()
            && let Ok(lease) = lookup(&mut churn.reader, &key, 4)
        {
            churn.held.push((key, lease));
        }
    }

    fn recovered(&mut self, churn: &mut Churn, w: &mut Witnesses) -> Result<(), String> {
        self.sample(churn);
        let unreturned = credits(churn).ok_or("the recovered storage reports no lease credits")?;
        self.marks.sample(UNRETURNED_CREDITS, unreturned);
        self.marks.check(UNRETURNED_CREDITS)?;
        self.leaked = None;
        let rows = churn.judged_recovery(w);
        let verdict = check(&Recorder::rebuilt(rows.clone()));
        if !verdict.satisfies(&[Obligation::Progress, Obligation::Bytes]) {
            return Err(format!("the funded recovery: {verdict:?}"));
        }
        continued(&rows, self.marks)
            .map_err(|refused| format!("the funded recovery: {refused}"))?;
        self.sample(churn);
        Ok(())
    }

    fn finished(&mut self, churn: &Churn) {
        self.sample(churn);
    }
}

/// Runs the storage phases of `plan` into `marks` and returns their report
/// lines.
///
/// # Errors
///
/// A lease credit outstanding once the churn released every holder, a
/// funded recovery the oracle does not credit with progress and exact
/// bytes or its continuation does not pass, a churn below its occupancy
/// or turnover, or an unfired witness, each named. A failing per-action
/// oracle panics, and the churn reports its seed, phase and action on
/// stderr.
pub(crate) fn storage_phases(plan: ChurnPlan, marks: &mut Marks) -> Result<Vec<String>, String> {
    let mut w = Witnesses {
        seed: plan.seed,
        ..Witnesses::default()
    };
    let mut churn = Churn::new(plan.seed, false, plan.collide);
    churn.phase = "long-run churn";
    let mut sampler = Sampler {
        marks,
        plan,
        leaked: None,
    };
    let (published, (occupied, checks)) = run_on(&mut churn, plan.actions, &mut w, &mut sampler)?;
    let turnovers = turnovers(Geometry::ORIGINAL, published)?;
    // The engine holds the fixture occupancy for two fifths of its checks
    // after warmup, which `run_on` requires of every seed, and the witness
    // fires at three fifths: a removed entry's units return at once, so one
    // seed's free units pass the occupancy ceiling between evictions more
    // often than the corpus's aggregate.
    if occupied * 5 >= checks * 3 {
        w.saw(Situation::OccupancySustained);
    }
    lifecycle_faults(&mut w, &mut sampler);
    poisoned_gate(&mut w, &mut sampler);
    let unfired = w.unfired();
    if !unfired.is_empty() {
        return Err(format!(
            "unfired churn witnesses: {unfired:?}; {occupied} of {checks} checks at the fixture occupancy"
        ));
    }
    let situations: usize = w.situations.iter().sum();
    let injected: usize = w.injected.iter().sum();
    let affected: usize = w.affected.iter().sum();
    Ok(vec![
        format!(
            "churn: seed {} collide {} actions {}; {occupied} of {checks} checks at the fixture occupancy; {published} units published, {turnovers} turnovers",
            plan.seed, plan.collide, plan.actions
        ),
        format!(
            "churn witnesses: {} situations fired {situations} times, {} fault members injected {injected} and affected {affected} times",
            w.situations.len(),
            w.injected.len()
        ),
    ])
}

/// The storage bounds are structural or observed at the pinned run plus
/// one: the lease-credit bound is the churn's held leases, the growth and
/// unreturned bounds are zero, and the command bound, the pinned run's
/// peak plus one, lies below the disk's queue depth, which refuses past it.
#[test]
fn the_storage_bounds_are_their_derived_ceilings() {
    let gate = Gate::parse(MANIFEST).unwrap();
    assert_eq!(gate.get(LEASE_CREDITS), super::HELD_LEASES as u64);
    assert_eq!(gate.get(DEVICE_GROWTH), 0);
    assert_eq!(gate.get(UNRETURNED_CREDITS), 0);
    let depth = super::super::volume_fixture::DEPTH;
    assert!(gate.get(DEVICE_COMMANDS) < u64::from(depth));
}
