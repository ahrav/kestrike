//! Traces of the lookup model, `quint/lookup.qnt`, for the replay against `Storage`.
//!
//! A directed trace follows one recipe of [`RECIPES`]; a seeded trace takes [`STEPS`] steps of the model's
//! own `step` under the seed beside its name in [`SEEDS`]. Every trace records under `#meta.lookup` its
//! recipe, which is empty for a seeded trace, its seed, its number of steps and the model's digest, and the
//! replay refuses a trace whose digest differs from the model's.

use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

use crate::fixtures::{self, Model, Style};

pub const NAME: &str = "lookup_fixtures";

pub(crate) const MODEL: Model = Model {
    tool: NAME,
    about: "Lookup model traces for the replay against `Storage`: the directed recipes and seeded runs of `step`.",
    name: "lookup",
    style: Style::Record,
    limit: Duration::from_secs(60),
};

pub const STEPS: usize = 16;
const RECIPE_SEED: u64 = 0x5e00;
#[rustfmt::skip]
pub const SEEDS: [(&str, u64); 6] = [
    ("step_a", 0x5e01), ("step_b", 0x5e02), ("step_c", 0x5e03), ("step_d", 0x5e04), ("step_e", 0x5e05), ("step_f", 0x5e06),
];

/// The model's check runs the first three recipes as checked runs.
#[rustfmt::skip]
pub const RECIPES: [(&str, &[&str]); 4] = [
    ("replaceUnderLease", &[
        "publish(0)", "lookup(0)", "replace(0)", "lookup(0)", "certify", "service", "drop(1)", "service",
    ]),
    ("removeThenReclaim", &["publish(0)", "remove(0)", "lookup(0)", "certify", "service"]),
    ("expiryAndClose", &["publish(0)", "publish(1)", "expire", "lookup(0)", "close", "lookup(1)", "remove(1)"]),
    ("twoKeys", &[
        "service", "certify", "certify", "publish(0)", "publish(1)", "lookup(1)", "remove(0)", "remove(1)", "certify",
        "service", "drop(2)", "service", "lookup(0)",
    ]),
];

pub fn run(top: &Path, args: &[OsString]) -> u8 {
    let traces = fixtures::traces(&MODEL, &RECIPES, RECIPE_SEED, &SEEDS, STEPS);
    fixtures::write(&MODEL, top, args, &traces, fixtures::keep)
}
