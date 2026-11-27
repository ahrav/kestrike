use std::ffi::OsString;
use std::path::Path;

use crate::fixtures::{self, Model, Style};

pub(crate) const MODEL: Model = Model {
    tool: "register_fixtures",
    about: "Register model traces for the replay against `Storage`: the directed recipes and seeded runs of `step`.",
    name: "register",
    style: Style::Record,
};

pub const STEPS: usize = 14;
const RECIPE_SEED: u64 = 0x3b00;
#[rustfmt::skip]
pub const SEEDS: [(&str, u64); 6] = [
    ("step_a", 0x3b01), ("step_b", 0x3b02), ("step_c", 0x3b03), ("step_d", 0x3b04), ("step_e", 0x3b05), ("step_f", 0x3b06),
];

#[rustfmt::skip]
pub const RECIPES: [(&str, &[&str]); 5] = [
    ("closeRacesAnEntry", &["register", "interval(0)", "intervalRacingClose(0)", "interval(0)", "register"]),
    ("leakedGuardBlocks", &["register", "leak(0)", "interval(0)", "drop(0)", "register", "interval(0)"]),
    ("limitAndReturn", &["register", "register", "register", "drop(0)", "registerRacingClose"]),
    ("forgottenHandles", &[
        "register", "register", "forget(1)", "register", "leak(0)", "forget(0)", "close", "register",
    ]),
    ("leakedAcrossTheClose", &["register", "leak(0)", "close", "interval(0)", "drop(0)"]),
];

pub fn run(top: &Path, args: &[OsString]) -> u8 {
    let traces = fixtures::traces(&MODEL, &RECIPES, RECIPE_SEED, &SEEDS, STEPS);
    fixtures::write(&MODEL, top, args, &traces, fixtures::keep)
}
