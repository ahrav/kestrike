//! Traces of the grace model, `quint/grace.qnt`, for the replay against the `grace` module.
//!
//! A directed trace follows one recipe of [`RECIPES`]; a seeded trace takes [`STEPS`] steps of the model's
//! own `step` under the seed beside its name in [`SEEDS`]. Every trace records under `#meta.grace` its
//! recipe, which is empty for a seeded trace, its seed, its number of steps and the model's digest, and the
//! replay refuses a trace whose digest differs from the model's.

use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

use crate::fixtures::{self, Model, Style};

pub const NAME: &str = "grace_fixtures";

pub(crate) const MODEL: Model = Model {
    tool: NAME,
    about: "Grace model traces for the replay against the `grace` module: the directed recipes and seeded runs of `step`.",
    name: "grace",
    style: Style::Record,
    limit: Duration::from_secs(60),
};

pub const STEPS: usize = 16;
const RECIPE_SEED: u64 = 0x6a00;
#[rustfmt::skip]
pub const SEEDS: [(&str, u64); 6] = [
    ("step_a", 0x6a01), ("step_b", 0x6a02), ("step_c", 0x6a03), ("step_d", 0x6a04), ("step_e", 0x6a05), ("step_f", 0x6a06),
];

/// The model's check runs the first four recipes as checked runs.
#[rustfmt::skip]
pub const RECIPES: [(&str, &[&str]); 7] = [
    ("readerBeforePass", &[
        "pin(0)", "observe(0)", "remove", "retire", "begin", "visit", "visit", "complete", "release",
    ]),
    ("passBeforeReader", &[
        "begin", "visit", "pin(0)", "observe(0)", "visit", "remove", "retire", "complete", "release",
    ]),
    ("releaseAfterUnpin", &[
        "pin(0)", "observe(0)", "remove", "retire", "begin", "visit", "visit", "complete", "release", "unpin(0)",
        "begin", "visit", "visit", "complete", "release", "reuse",
    ]),
    ("terminalRefusesPins", &["pin(0)", "elsewhere", "elsewhere", "pin(1)", "pin(0)"]),
    ("refusals", &[
        "pin(0)", "pin(0)", "observe(0)", "unpin(0)", "unpin(1)", "remove", "pin(1)", "observe(1)", "begin",
    ]),
    ("keptCertificate", &[
        "begin", "visit", "visit", "complete", "begin", "pin(0)", "visit", "visit", "complete", "unpin(0)",
    ]),
    ("closingRetirement", &[
        "elsewhere", "pin(1)", "remove", "retire", "begin", "visit", "visit", "complete", "release", "elsewhere",
        "pin(0)",
    ]),
];

pub fn run(top: &Path, args: &[OsString]) -> u8 {
    let traces = fixtures::traces(&MODEL, &RECIPES, RECIPE_SEED, &SEEDS, STEPS);
    fixtures::write(&MODEL, top, args, &traces, fixtures::keep)
}
