//! Traces of the builder-escrow model, `quint/escrow.qnt`, for the replay against `Storage`.
//!
//! A directed trace follows one recipe at its volume; a seeded trace takes [`STEPS`] steps of the model's
//! own `step` under the seed its name carries, at the volume beside the seed. Every trace records under
//! `#meta.escrow` the model's digest, its seed, its number of steps, its volume and a directed trace's
//! recipe, and the replay refuses a trace whose digest differs from the model's.

use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

use crate::fixtures::{self, Model, Style, Trace, case};
use crate::json::{Integer, Value};

pub(crate) const MODEL: Model = Model {
    tool: "escrow_fixtures",
    about: "Builder-escrow model traces for the replay against `Storage`: the directed recipes and seeded runs of `step`.",
    name: "escrow",
    style: Style::Format,
    limit: Duration::from_secs(120),
};

pub const STEPS: usize = 12;
const RECIPE_SEED: u64 = 0xe4f;
#[rustfmt::skip]
pub const SEEDS: [(u64, u64); 8] = [
    (0xe50, 316), (0xe51, 316), (0xe52, 316), (0xe53, 316), (0xe54, 316), (0xe55, 316), (0xe56, 315),
    (0xe57, 315),
];

/// The first four recipes equal `RUNS` of `quint/escrow_check.py`, which `quint/check.py` runs as checked
/// runs.
#[rustfmt::skip]
pub const RECIPES: [(&str, &[&str], u64); 6] = [
    ("an_exact_promise_succeeds_and_a_short_one_refuses", &[
        "claim", "claim", "promise(1, 3)", "promise(2, 2)", "place(1)",
    ], 316),
    ("a_claim_beside_a_promise_spares_the_promised_units", &[
        "promise(1, 3)", "claim", "claim", "place(1)", "unclaim", "release(1)", "service",
    ], 316),
    ("two_builders_interleave_and_each_exit_refunds_once", &[
        "promise(1, 2)", "promise(2, 2)", "place(2)", "place(1)", "cancel(1)", "place(2)", "release(2)", "service",
        "service", "service",
    ], 316),
    ("the_reserve_refuses_a_promise_of_exactly_the_allocatable_units", &[
        "claim", "claim", "promise(1, 3)", "unclaim", "promise(1, 3)",
    ], 315),
    // Each exit of each placement cut: an unplaced cancel and drop, a partial cancel, a complete cancel and
    // drop, and service returning a parked sequence one extent per call, then idle.
    ("every_exit_at_every_cut", &[
        "promise(1, 2)", "cancel(1)", "promise(2, 3)", "release(2)", "service", "promise(1, 3)", "place(1)",
        "cancel(1)", "promise(2, 2)", "place(2)", "place(2)", "release(2)", "service", "service", "service",
    ], 316),
    // A claim refused beside two promises, a cancel of an unplaced builder beside a complete one, a promise
    // refused beside two claims, the complete builder's cancel and an exact promise, then both claims return.
    ("refusals_beside_promises_and_claims", &[
        "promise(1, 3)", "promise(2, 2)", "claim", "place(1)", "place(1)", "place(1)", "cancel(2)", "claim", "claim",
        "promise(2, 2)", "cancel(1)", "promise(2, 3)", "unclaim", "unclaim",
    ], 316),
];

pub fn run(top: &Path, args: &[OsString]) -> u8 {
    let directed = RECIPES
        .iter()
        .map(|&(name, recipe, volume)| trace(name.to_owned(), RECIPE_SEED, Some(recipe), volume));
    let seeded = SEEDS
        .iter()
        .map(|&(seed, volume)| trace(format!("step_{seed:x}"), seed, None, volume));
    let traces: Vec<Trace> = directed.chain(seeded).collect();
    fixtures::write(&MODEL, top, args, &traces, fixtures::keep)
}

fn trace(name: String, seed: u64, recipe: Option<&'static [&'static str]>, volume: u64) -> Trace {
    let case = |steps, recipe: Option<&[&str]>| case::escrow(steps, &volume.to_string(), recipe);
    Trace::new(
        name,
        seed,
        recipe,
        STEPS,
        case,
        vec![("volume", Value::Integer(Integer::from(volume)))],
    )
}
