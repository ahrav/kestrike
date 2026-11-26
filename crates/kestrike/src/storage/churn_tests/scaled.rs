//! The scaled churn runs: [`RUN`] fixes the action count and the seeds of
//! every member, and the runs read nothing else, no environment variable,
//! path or clock.
//!
//! A member is one seed on one geometry, churned on its own engine for the
//! run's action count with every per-action oracle of [`Churn::check`]
//! active, then recovered and run through its terminal faults by
//! [`run_on`]; seed `s` routes keys through one-fingerprint groups when
//! `s % 4 == 3`, as the ordinary corpus does. Each member that passes
//! prints one `scaled:` line naming its geometry, seed and action count, so
//! a run's output names every member it completed.
//!
//! The seed run churns every seed on the original geometry, then runs the
//! lifecycle and poisoned-gate phases, and requires the whole witness set
//! of the ordinary corpus with the fixture occupancy across the seeds. The
//! geometry run churns every seed on each larger geometry and requires,
//! per geometry, the occupancy and the reserve and fragmentation witnesses
//! of the ordinary larger-geometry test.

use super::{
    Churn, Geometry, Member, Situation, Witnesses, lifecycle_faults, poisoned_gate, run_on,
    turnovers,
};

/// One scaled run: the action count of every member and the seeds
/// `0..seeds`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Scaled {
    pub(crate) actions: usize,
    pub(crate) seeds: u64,
}

/// The long-run lane's scaled run: 409,600 actions for each of the seeds
/// whose witnesses reach the churn records.
pub(crate) const RUN: Scaled = Scaled {
    actions: 409_600,
    seeds: super::SEEDS,
};

/// The geometry as a member line names it.
fn label(geometry: Geometry) -> String {
    format!(
        "units={} slots={} chunk={} reserve={}",
        geometry.units, geometry.slots, geometry.chunk_len, geometry.reserve
    )
}

/// Runs every seed of `scaled` on `geometry`, each on its own engine, into
/// `w` and `lines`; returns the checks after warmup at the fixture
/// occupancy and all checks, summed over the seeds.
///
/// # Errors
///
/// A member below its occupancy or turnover, named by geometry and seed. A
/// failing per-action oracle panics, and the churn reports its seed, phase
/// and action on stderr.
fn members(
    scaled: Scaled,
    geometry: Geometry,
    w: &mut Witnesses,
    lines: &mut Vec<String>,
) -> Result<(usize, usize), String> {
    let (mut occupied, mut checks) = (0, 0);
    for seed in 0..scaled.seeds {
        let collide = seed % 4 == 3;
        let mut seen = Witnesses {
            seed,
            ..Witnesses::default()
        };
        let mut churn = Churn::over(geometry, seed, false, collide, &[]);
        churn.phase = "scaled";
        let member = format!("{} seed {seed}", label(geometry));
        let (published, (at, of)) = run_on(&mut churn, scaled.actions, &mut seen, &mut ())
            .map_err(|refused| format!("{member}: {refused}"))?;
        let turned =
            turnovers(geometry, published).map_err(|refused| format!("{member}: {refused}"))?;
        w.merge(&seen);
        occupied += at;
        checks += of;
        lines.push(format!(
            "scaled: {member} collide {collide} actions {}: complete; {at} of {of} checks at the fixture occupancy, {published} units published, {turned} turnovers",
            scaled.actions
        ));
    }
    Ok((occupied, checks))
}

/// The fixture occupancy across a scaled run's members: two thirds of their
/// checks after warmup.
///
/// # Errors
///
/// Members under two thirds, named by `what`.
fn sustained(what: &str, occupied: usize, checks: usize) -> Result<(), String> {
    if occupied * 3 < checks * 2 {
        return Err(format!(
            "{what}: {occupied} of {checks} checks at the fixture occupancy, under two thirds"
        ));
    }
    Ok(())
}

/// Runs the seed run of `scaled` and returns its report lines: one per
/// member, then the witness counts.
///
/// # Errors
///
/// A member below its occupancy or turnover, the seeds under the fixture
/// occupancy, or an unfired witness, each named.
pub(crate) fn seeds(scaled: Scaled) -> Result<Vec<String>, String> {
    let mut w = Witnesses::default();
    let mut lines = Vec::new();
    let geometry = Geometry::ORIGINAL;
    let (occupied, checks) = members(scaled, geometry, &mut w, &mut lines)?;
    sustained("the seeds", occupied, checks)?;
    w.seed = super::SEEDS;
    w.saw(Situation::OccupancySustained);
    lifecycle_faults(&mut w, &mut ());
    poisoned_gate(&mut w, &mut ());
    let unfired = w.unfired();
    if !unfired.is_empty() {
        return Err(format!("unfired scaled witnesses: {unfired:?}"));
    }
    lines.push(format!(
        "scaled: seed witnesses: {} situations fired {} times, {} fault members injected {} and affected {} times; {occupied} of {checks} checks at the fixture occupancy; lifecycle and poisoned-gate phases ran",
        w.situations.len(),
        w.situations.iter().sum::<usize>(),
        w.injected.len(),
        w.injected.iter().sum::<usize>(),
        w.affected.iter().sum::<usize>(),
    ));
    Ok(lines)
}

/// Runs the geometry run of `scaled` and returns its report lines: one
/// per member, then one per geometry.
///
/// # Errors
///
/// A member below its occupancy or turnover, a geometry under the fixture
/// occupancy, or a reserve or fragmentation witness a geometry never
/// fired, each named.
pub(crate) fn geometries(scaled: Scaled) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    for geometry in Geometry::LARGER {
        let mut w = Witnesses::default();
        let (occupied, checks) = members(scaled, geometry, &mut w, &mut lines)?;
        let name = label(geometry);
        sustained(&name, occupied, checks)?;
        for situation in [
            Situation::ReserveEquality,
            Situation::ReserveOneShortRefusal,
            Situation::FragmentedNoFitAboveReserve,
        ] {
            if w.situations[situation as usize] == 0 {
                return Err(format!("{name}: {situation:?} never fired"));
            }
        }
        for member in [
            Member::F1ExactBound,
            Member::F1OneShortBound,
            Member::F1Fragmentation,
        ] {
            if w.affected[member as usize] == 0 {
                return Err(format!("{name}: {member:?} never affected an operation"));
            }
        }
        lines.push(format!(
            "scaled: geometry {name} witnesses: reserve and fragmentation fired; {occupied} of {checks} checks at the fixture occupancy"
        ));
    }
    Ok(lines)
}

/// [`RUN`] cut to an action count too short to turn its capacity over
/// fails by its first member's geometry and seed, and prints no member
/// line for it.
#[test]
fn a_short_run_fails_by_its_first_member() {
    let short = Scaled {
        actions: 120,
        ..RUN
    };
    let refused = seeds(short).unwrap_err();
    assert!(
        refused.starts_with("units=64 slots=16 chunk=8192 reserve=2 seed 0: "),
        "{refused}"
    );
    let refused = geometries(short).unwrap_err();
    assert!(
        refused.starts_with("units=65 slots=33 chunk=4096 reserve=2 seed 0: "),
        "{refused}"
    );
}
