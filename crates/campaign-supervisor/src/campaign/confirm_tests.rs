//! `confirm`'s admission of a sweep's suspects and the outcome it reports.

use super::*;
use crate::campaign::Request;
use crate::store::fixture::Case;

/// The admission listing with the control profile `planted` added.
fn listing() -> Listing {
    let text = include_str!("../../testdata/admission-listing.txt");
    let upload = text
        .lines()
        .find(|line| line.starts_with("profile: upload class=live"))
        .unwrap();
    let planted = upload.replace("upload class=live", "planted class=control");
    Listing::parse(&text.replacen(upload, &format!("{planted}\n{upload}"), 1)).unwrap()
}

fn word(value: &str) -> Text {
    super::super::text(value).unwrap()
}

/// The pins of an archive whose build digest repeats `build`.
fn pins(build: char) -> Pins {
    Pins {
        build: word(&build.to_string().repeat(64)),
        executable: word(&"e".repeat(64)),
        platform: word("x86_64-linux"),
        toolchain: word("rustc 1.99.0"),
    }
}

/// The suspect a sweep of the archive with `pins` lists for run `run` of
/// `profile`.
fn suspect(pins: &Pins, profile: &str, run: u64) -> Suspect {
    let request = Request {
        profile: word(profile),
        campaign: word("host"),
        run,
        attempts: 3,
        counts: BTreeMap::new(),
    };
    let (job, _) = super::super::freeze::freeze(&listing(), pins.clone(), &request).unwrap();
    Suspect {
        request,
        seed: job.seed(),
        build: pins.build.clone(),
    }
}

/// Whether `store` holds the campaign job of `suspect` from the archive
/// with `pins`.
fn admitted(store: &Store, pins: &Pins, suspect: &Suspect) -> bool {
    super::super::admit(
        store,
        &listing(),
        pins.clone(),
        word("/archive"),
        &suspect.request,
        Purpose::Campaign,
    )
    .unwrap()
    .existing
}

/// A root that another user can write, here one with group write
/// permission, is rejected before the command reads its cgroup or writes
/// under the root.
#[test]
fn a_root_another_user_can_write_is_rejected() {
    use std::os::unix::fs::PermissionsExt;
    let case = Case::new();
    let root = case.root.join("sweep");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("sweep.json"), b"{}").unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o770)).unwrap();
    let absent = case.root.join("no-cgroup");
    let confirmed = confirm(&root, &case.root.join("archive"), absent, 1);
    assert!(
        matches!(confirmed.as_ref().err(), Some(Error::Rejected(_))),
        "{:?}",
        confirmed.err()
    );
    assert!(!root.join("confirm").exists());
}

/// A root no sweep has written holds no suspects, so `confirm` rejects
/// it, as `sweep-status` does, and creates nothing: a mistyped root is
/// not read as a sweep with nothing to confirm.
#[test]
fn a_root_no_sweep_wrote_is_rejected_and_left_absent() {
    let case = Case::new();
    let root = case.root.join("swep");
    let absent = case.root.join("no-cgroup");
    let confirmed = confirm(&root, &case.root.join("archive"), absent, 1);
    assert!(
        matches!(confirmed.as_ref().err(), Some(Error::Rejected(reason)) if reason.contains("no sweep")),
        "{:?}",
        confirmed.err()
    );
    assert!(!root.exists());
}

/// A suspect admission refuses, here one of a control profile, is reported
/// with its reason, and the suspects after it are admitted.
#[test]
fn a_suspect_admission_refuses_is_reported_and_the_rest_are_admitted() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let pins = pins('b');
    let suspects = [suspect(&pins, "planted", 0), suspect(&pins, "upload", 1)];
    let refused = admit_suspects(
        &store,
        &listing(),
        &pins,
        &word("/archive"),
        &pins.build,
        &suspects,
    )
    .unwrap();
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert!(refused[0].contains("planted") && refused[0].contains("expect a pass"));
    assert!(admitted(&store, &pins, &suspects[1]));
}

/// A suspect that names another archive's build rejects the command,
/// which admits none of its suspects, the ones before that suspect
/// included: this archive's job for the run has another seed.
#[test]
fn suspects_swept_from_another_archive_admit_nothing() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let (swept, given) = (pins('b'), pins('c'));
    let suspects = [suspect(&given, "upload", 0), suspect(&swept, "upload", 1)];
    let refused = admit_suspects(
        &store,
        &listing(),
        &given,
        &word("/archive"),
        &given.build,
        &suspects,
    );
    assert!(
        matches!(&refused, Err(Error::Rejected(reason)) if reason.contains("another archive")),
        "{refused:?}"
    );
    assert!(!admitted(&store, &given, &suspects[0]));
}

/// An archive of another build than the root's is rejected whatever the
/// suspects left to read, so a `confirm` with no unread suspect does not
/// go on to dispatch the queued jobs of the root with it.
#[test]
fn an_archive_of_another_build_than_the_roots_is_rejected_with_no_suspect_left() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let (swept, given) = (pins('b'), pins('c'));
    let refused = admit_suspects(
        &store,
        &listing(),
        &given,
        &word("/archive"),
        &swept.build,
        &[],
    );
    assert!(
        matches!(
            &refused,
            Err(Error::Rejected(reason))
                if reason.contains(swept.build.as_str()) && reason.contains(given.build.as_str())
        ),
        "{refused:?}"
    );
}

/// A suspect whose job has another seed than the root the sweep ran holds
/// the command, which admits none of its suspects.
#[test]
fn a_job_with_another_seed_than_the_swept_root_holds() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let pins = pins('b');
    let mut suspects = [suspect(&pins, "upload", 0), suspect(&pins, "upload", 1)];
    suspects[1].seed ^= 1;
    let refused = admit_suspects(
        &store,
        &listing(),
        &pins,
        &word("/archive"),
        &pins.build,
        &suspects,
    );
    assert!(matches!(refused, Err(Error::Held(_))), "{refused:?}");
    assert!(!admitted(&store, &pins, &suspects[0]));
}

/// A dispatch that a refusal or a rejection stopped fails the command with
/// that cause, and the output names it; a dispatch that ran its window
/// does not.
#[test]
fn a_stopped_dispatch_fails_the_command_with_its_cause() {
    let outcome = |report: &Report| outcome(Path::new("/state"), 2, &[], report, json!([]));
    assert!(outcome(&Report::default()).stopped.is_none());
    let rejected = Report {
        rejections: vec!["cores exceed the cgroup's limit".into()],
        ..Report::default()
    };
    let confirmed = outcome(&rejected);
    assert!(
        matches!(&confirmed.stopped, Some(Error::Rejected(reason)) if reason.contains("cores"))
    );
    assert_eq!(confirmed.value["rejections"][0], rejected.rejections[0]);
    let held = Report {
        refusals: vec!["the store is held".into()],
        ..Report::default()
    };
    let confirmed = outcome(&held);
    assert!(matches!(confirmed.stopped, Some(Error::Held(_))));
    assert_eq!(confirmed.value["refusals"][0], held.refusals[0]);
}

/// The output counts the suspects admission refused and lists their
/// reasons.
#[test]
fn the_output_lists_the_suspects_admission_refused() {
    let refused = ["run 0 of planted: campaign profile must expect a pass".to_owned()];
    let confirmed = outcome(
        Path::new("/state"),
        1,
        &refused,
        &Report::default(),
        json!([]),
    );
    assert_eq!(confirmed.value["suspects"], 1);
    assert_eq!(confirmed.value["refused"], 1);
    assert_eq!(confirmed.value["refused_reasons"][0], refused[0]);
}

#[test]
fn the_output_names_its_dispatch_as_the_host_runner_reads_it() {
    use sim_host::runner::{DISPATCH, INTERRUPTED, QUEUE_EMPTY};

    use crate::campaign::dispatch::State;
    let confirmed = outcome(Path::new("/state"), 0, &[], &Report::default(), json!([]));
    assert_eq!(confirmed.value[DISPATCH], QUEUE_EMPTY);
    assert_eq!(
        serde_json::to_value(State::Interrupted).unwrap(),
        INTERRUPTED
    );
}

/// A slot count whose cores or memory pass a `u64` is rejected, as a
/// count the budgets do not cover is.
#[test]
fn a_slot_count_past_the_budget_arithmetic_is_rejected() {
    for slots in [u64::MAX, 1 << 33] {
        let refused = configuration(slots).err();
        assert!(
            matches!(refused, Some(Error::Rejected(_))),
            "{slots} slots: {refused:?}"
        );
    }
}
