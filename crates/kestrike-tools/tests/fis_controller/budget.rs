//! The campaign budget of the checked-in profiles under the controller's default.

use kestrike_tools::fis_controller::{
    ATTACHMENT_MODES, DEFAULT_BUDGET_SECONDS, check_operator, episode_bound,
};
use kestrike_tools::json::Value;

use crate::fis_support::{hardware_manifest, member, operator, profiles};

/// One campaign runs the profiles of one attachment mode, since one volume's Multi-Attach setting admits
/// one; each mode's checked-in profiles under a 60 s effect timeout and 60 s AWS calls fit the
/// controller's default budget.
#[test]
fn the_default_budget_holds_the_checked_in_profiles_under_a_minute_of_effect_timeout() {
    let profiles = profiles();
    let Value::Object(declared) = member(&profiles, &["profiles"]) else {
        panic!("the checked-in profiles are an object");
    };
    let operator = check_operator(&operator("60")).expect("the contract is admitted");
    for mode in ATTACHMENT_MODES {
        let chosen: Vec<&Value> = declared
            .iter()
            .map(|(_, profile)| profile)
            .filter(|profile| member(profile, &["attachment"]) == &Value::String(mode.into()))
            .collect();
        assert!(!chosen.is_empty(), "a checked-in profile runs under {mode}");
        let needed: f64 = chosen
            .iter()
            .map(|profile| {
                episode_bound(profile, &operator, 60.0, &hardware_manifest())
                    .expect("each checked-in profile has an episode bound")
            })
            .sum();
        assert!(
            needed <= f64::from(DEFAULT_BUDGET_SECONDS),
            "{mode}: {needed}"
        );
    }
}
