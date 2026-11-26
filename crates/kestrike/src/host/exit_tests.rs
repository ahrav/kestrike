use super::exit::{Exit, Refusal, Rerun};
use crate::failover::restart::Check;
use crate::failover::retire::Target;
use crate::storage::store_tests::record;

/// HOST-LOSS-KEEPS-VOLUME: a retirement request, a refusal and a retired volume park the process, so its supervisor
/// starts no new incarnation over them; every other kind, a rerun of any cause included, ends the process. The match
/// stops compiling when `Exit` gains a kind; the table checks that kind once a row names it.
#[test]
fn each_exit_kind_either_parks_or_ends_the_process() {
    let target = Target::of(&record());
    let table = [
        (Exit::Stopped, false),
        (Exit::Rerun(Rerun::ControllerEvent), false),
        (Exit::Held { recovery: target }, false),
        (Exit::Deposed, false),
        (Exit::Retire(target), true),
        (Exit::Refused(Refusal::Restart(Check::SuffixOnly)), true),
        (Exit::Retired, true),
        (Exit::Fault("unreadable configuration".to_owned()), false),
    ];
    for (exit, parks) in &table {
        match exit {
            Exit::Stopped
            | Exit::Rerun(_)
            | Exit::Held { .. }
            | Exit::Deposed
            | Exit::Retire(_)
            | Exit::Refused(_)
            | Exit::Retired
            | Exit::Fault(_) => {}
        }
        assert_eq!(exit.parks(), *parks, "{exit:?}");
    }
    for cause in [
        Rerun::ControllerEvent,
        Rerun::RecordedHolder,
        Rerun::Poisoned,
        Rerun::Unwound,
        Rerun::Takeover,
        Rerun::Records,
        Rerun::RoleChanged,
        Rerun::Records,
        Rerun::Unactivated,
        Rerun::Withdrawn,
        Rerun::Planned,
    ] {
        assert!(!Exit::Rerun(cause).parks(), "{cause:?}");
    }
}
