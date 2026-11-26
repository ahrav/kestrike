//! Each control runs the mixed phase's scenarios at the manifest's root.
//! The long scenario passes while a disabled, always-deferring or rejected
//! upload earns no pass; each publication ingredient and an unbroken
//! binding are necessary for that witness; the phase without the scenarios
//! arming any one required witness is unsuccessful; and an early source
//! release fails the custody obligation. The mixed bounds are checked
//! against their derivations.

use crate::sim::action::ActionKind;
use crate::sim::long_run_tests::{
    AUDIT_RECORDS, CAPTURES, COPY_BYTES, Gate, LIVE_UPLOADS, MANIFEST, MIXED_ROOT, REGISTRY,
    SOURCE_BYTES, WITNESS_LOG,
};

use super::super::super::datagram::HEADER_LEN;
use super::super::super::observe::{Failure, Witnesses};
use super::super::super::owner_tests::key;
use super::super::super::rules::MANIFEST as RULES;
use super::super::super::upload::UploadOutcome;
use super::super::{Geometry, OBJECT_LEN, PUT_KEY, Ran, nic_return_link, upload_code};
use super::{
    NIC_RETURN, PUBLISHED_READ, REQUIRED, Scenario, WITNESS_LIMIT, exact_read, recorded_upload,
    required, run, scenarios, witness,
};

/// A named removal of one observation from a run, given the outcome code
/// of a publication.
type Edit = (&'static str, fn(&mut Ran, u64));

fn pinned() -> Vec<Scenario> {
    scenarios(Gate::parse(MANIFEST).unwrap().get(MIXED_ROOT))
}

fn named(name: &str) -> Scenario {
    let found = pinned().into_iter().find(|scenario| scenario.name == name);
    found.unwrap()
}

fn fires(scenario: &Scenario, ran: &Ran, name: &str) -> Result<(), Failure> {
    let mut w = Witnesses::new(WITNESS_LIMIT);
    let required = REQUIRED.iter().find(|required| required.name == name);
    let required = required.expect("a required witness");
    w.require(required.name, required.needs);
    witness(scenario, ran, 0, &mut w);
    w.verdict()
}

/// Each control changes one input of the long scenario, whose planned run
/// is the passing baseline: a profile that drops the upload's kinds, a
/// supplier that always defers and a storage too small for the upload each
/// end it `Inconclusive` at a named limit.
#[test]
fn a_disabled_deferred_or_rejected_upload_earns_no_pass() {
    let baseline = run(&named("long"));
    assert!(baseline.is_ok(), "{:?}", baseline.err());
    let mut disabled = named("long");
    disabled.profile.declared.retain(|kind| {
        !matches!(
            kind,
            ActionKind::PutInvoke
                | ActionKind::PutPrepare
                | ActionKind::Supply
                | ActionKind::PutOutcome
        )
    });
    let mut deferred = named("long");
    deferred.plan.withhold = u32::MAX;
    let mut rejected = named("long");
    rejected.plan.geometry = Geometry::Cramped;
    for (name, scenario) in [
        ("disabled", disabled),
        ("deferred", deferred),
        ("rejected", rejected),
    ] {
        let Err(refused) = run(&scenario) else {
            panic!("{name} passed");
        };
        assert!(refused.contains(": inconclusive at "), "{name}: {refused}");
    }
}

/// The result-replay scenario fires the publication witness. Each edit of
/// that run leaves it unfired: removing the admission, the write
/// completion, the receipt, the new binding, the client's success or the
/// exact read, or recording another binding of the key on the turn each
/// exact read decided.
#[test]
fn removing_any_publication_ingredient_leaves_the_witness_unfired() {
    let scenario = named("result-replay");
    let ran = run(&scenario).unwrap();
    assert_eq!(fires(&scenario, &ran, PUBLISHED_READ), Ok(()));
    let published = upload_code(UploadOutcome::Published);
    let edits: [Edit; 7] = [
        ("admission", |ran, _| {
            for seen in &mut ran.seen {
                seen.upload = seen.upload.map(|(attempt, _)| (attempt, 0));
            }
        }),
        ("write completion", |ran, _| {
            for seen in &mut ran.seen {
                seen.written = 0;
            }
        }),
        ("receipt", |ran, _| {
            for seen in &mut ran.seen {
                seen.receipt = seen.receipt.map(|(_, grant)| (0, grant));
            }
        }),
        ("binding", |ran, _| {
            for seen in &mut ran.seen {
                seen.binding = None;
            }
        }),
        ("client success", |ran, published| {
            ran.acts
                .retain(|act| !(act.kind == ActionKind::PutOutcome && act.outcome == published));
        }),
        ("exact read", |ran, _| {
            for decided in &mut ran.decided {
                decided.exact = false;
            }
        }),
        ("unbroken binding", |ran, _| {
            for decided in exact_read(ran, key(PUT_KEY), 0, None) {
                ran.seen[decided].binding = Some((u32::MAX, u32::MAX));
            }
        }),
    ];
    for (name, edit) in edits {
        let mut edited = run(&scenario).unwrap();
        edit(&mut edited, published);
        assert_eq!(
            fires(&scenario, &edited, PUBLISHED_READ),
            Err(Failure::Unsuccessful("a required witness never fired")),
            "without the {name}"
        );
    }
}

#[test]
fn a_binding_ahead_of_the_write_leaves_the_publication_witness_unfired() {
    let scenario = named("result-replay");
    let mut ran = run(&scenario).unwrap();
    assert_eq!(fires(&scenario, &ran, PUBLISHED_READ), Ok(()));
    let seen = &mut ran.seen;
    let admitted = seen.iter().position(|seen| {
        seen.upload.is_some_and(|(_, serial)| serial != 0)
            && seen.receipt.is_some_and(|(_, grant)| grant > 0)
    });
    let admitted = admitted.unwrap();
    let (incumbent, before) = (seen[admitted].binding, seen[admitted].written);
    let written = (admitted + 1..seen.len()).find(|&t| seen[t].written > before);
    let written = written.unwrap();
    assert!(
        written > admitted + 1,
        "admitted at {admitted}, written at {written}"
    );
    let bound = (written..seen.len())
        .find(|&t| seen[t].binding.is_some() && seen[t].binding != incumbent)
        .unwrap();
    let binding = seen[bound].binding;
    for early in &mut seen[admitted + 1..bound] {
        early.binding = binding;
    }
    assert_eq!(
        fires(&scenario, &ran, PUBLISHED_READ),
        Err(Failure::Unsuccessful("a required witness never fired"))
    );
}

#[test]
fn a_release_ahead_of_the_nic_return_leaves_its_witness_unfired() {
    let scenario = named("boundary-tiny");
    let mut ran = run(&scenario).unwrap();
    assert_eq!(fires(&scenario, &ran, NIC_RETURN), Ok(()));
    let seen = &mut ran.seen;
    let held = seen
        .iter()
        .position(|seen| seen.device_held > 0 && seen.nic[0] > 0);
    let held = held.unwrap();
    let holding = seen[held].device_held;
    let returned = (held + 1..seen.len()).find(|&t| {
        nic_return_link(&ran.report.turns[t].event) == Some(0)
            && seen[t].withheld[0] < seen[t - 1].withheld[0]
    });
    let returned = returned.unwrap();
    assert!(
        returned > held + 1,
        "held at {held}, returned at {returned}"
    );
    let released = (returned..seen.len()).find(|&t| seen[t].device_held < holding);
    let released = released.unwrap();
    let left = seen[released].device_held;
    for early in &mut seen[held + 1..released] {
        early.device_held = left;
    }
    assert_eq!(
        fires(&scenario, &ran, NIC_RETURN),
        Err(Failure::Unsuccessful("a required witness never fired"))
    );
}

/// Over every scenario's run the phase's witness verdict passes. Without
/// the scenarios that arm any one required witness, the verdict is
/// unsuccessful because that witness was never armed.
#[test]
fn dropping_the_scenarios_arming_any_witness_leaves_the_phase_unsuccessful() {
    let scenarios = pinned();
    let runs: Vec<Ran> = scenarios
        .iter()
        .map(|scenario| run(scenario).unwrap())
        .collect();
    let phase = |kept: &dyn Fn(&Scenario) -> bool| {
        let mut w = required();
        for (index, (scenario, ran)) in scenarios.iter().zip(&runs).enumerate() {
            if kept(scenario) {
                witness(scenario, ran, index as u64, &mut w);
            }
        }
        w.verdict()
    };
    assert_eq!(phase(&|_| true), Ok(()));
    for required in &REQUIRED {
        let refused = phase(&|scenario| !scenario.arms.contains(&required.name));
        assert_eq!(
            refused,
            Err(Failure::Unsuccessful("a required witness was never armed")),
            "without the scenarios arming {}",
            required.name
        );
    }
}

/// The recorded upload's rows pass through the continuation; moving the
/// source retention's release ahead of the first receipt ACK fails the
/// custody obligation by its rule.
#[test]
fn an_early_source_release_fails_the_custody_obligation() {
    let mut marks = Gate::parse(MANIFEST).unwrap().marks();
    assert!(recorded_upload(false, &mut marks).is_ok());
    let refused = recorded_upload(true, &mut marks).unwrap_err();
    assert!(
        refused.contains("Custody")
            && refused.contains(
                "retransmission retention ended before the receipt base passed its fragment"
            ),
        "{refused}"
    );
}

/// The mixed phase's structural bounds equal their sources, and every
/// depth bound lies below the fixture limit that refuses its quantity, so
/// each mark can pass its bound while the fixture still admits it.
#[test]
fn the_mixed_bounds_are_their_derived_ceilings() {
    let gate = Gate::parse(MANIFEST).unwrap();
    assert_eq!(gate.get(LIVE_UPLOADS), 1);
    assert_eq!(gate.get(SOURCE_BYTES), u64::from(OBJECT_LEN));
    assert_eq!(gate.get(REGISTRY), 2);
    assert_eq!(gate.get(COPY_BYTES) % HEADER_LEN as u64, 0);
    assert!(gate.get(CAPTURES) < RULES.captures as u64);
    assert!(gate.get(AUDIT_RECORDS) < RULES.records as u64);
    assert!(gate.get(WITNESS_LOG) < WITNESS_LIMIT as u64);
}
