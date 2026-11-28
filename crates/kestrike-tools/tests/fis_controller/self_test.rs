//! The write's whole-or-nothing case and the poll's cut case, on the library's write and on the
//! fake clock.

use std::fs;
use std::time::Duration;

use kestrike_tools::fis_controller::{self, Deadlines, duration, write_file};
use kestrike_tools::host_stop::{Delivered, Record};

use crate::fis_support::clock::Clock;
use crate::fis_support::steps::Steps;
use crate::fis_support::{Scratch, listing};

/// The write replaces the file in one step from a synced partial file: a failed sync leaves the
/// previous version and no partial file, and the directory's making syncs each parent that gained
/// an entry, then the file's own directory.
#[test]
fn a_file_is_written_whole_or_left_as_it_was_and_its_directories_are_synced() {
    let scratch = Scratch::new("self-test-write");
    let state = scratch.path().join("state");
    fs::create_dir(&state).expect("the state directory is made");
    let target = state.join("deep/er/file.json");
    let files = Steps::default();
    write_file(&files, &target, "one\n").expect("the file is written");
    assert_eq!(fs::read_to_string(&target).expect("reads"), "one\n");
    assert_eq!(
        *files.opened.borrow(),
        [
            state.clone(),
            state.join("deep"),
            target.parent().expect("a parent").to_path_buf()
        ],
        "each new parent, then the file's"
    );
    let failing = Steps {
        file_sync: true,
        probe: Some(target.with_file_name("file.json.partial")),
        ..Steps::default()
    };
    assert!(write_file(&failing, &target, "two\n").is_err());
    assert_eq!(
        fs::read_to_string(&target).expect("reads"),
        "one\n",
        "the previous version stands"
    );
    assert_eq!(
        *failing.probed.borrow(),
        Some(true),
        "the partial file stood at the failure"
    );
    assert_eq!(
        listing(target.parent().expect("a parent")),
        ["file.json"],
        "no partial file is left"
    );
}

/// A poll wider than a window never carries a loop past that window's deadline or the run's: each
/// sleep is cut at the earliest of them, and a deadline already past means no sleep.
#[test]
fn a_polling_sleep_is_cut_at_the_deadline_it_polls_toward() {
    let delivered = Delivered::new();
    let mut record = Record::new(&delivered);
    let mut clock = Clock::at(1000.0);
    let mut deadlines = Deadlines::new(100.0, 10.0).expect("the seconds are admitted");
    let now = |clock: &Clock| fis_controller::now(clock).expect("the clock reads");
    let window = now(&clock) + 0.2;
    deadlines
        .nap(&mut clock, &mut record, &[Some(window)])
        .expect("the poll sleeps");
    deadlines.set_run(Some(now(&clock) + 0.2));
    deadlines
        .nap(&mut clock, &mut record, &[])
        .expect("the poll sleeps");
    deadlines.set_run(None);
    let past = now(&clock) - 5.0;
    deadlines
        .nap(&mut clock, &mut record, &[Some(past)])
        .expect("the poll sleeps");
    let sleeps = clock.sleeps();
    assert!(
        sleeps[0] <= duration(0.2) + Duration::from_nanos(1),
        "the sleep ends at the window's deadline: {sleeps:?}"
    );
    assert!(
        sleeps[1] <= duration(0.2) + Duration::from_nanos(1),
        "the sleep ends at the run deadline: {sleeps:?}"
    );
    assert_eq!(
        sleeps[2],
        Duration::ZERO,
        "a deadline already passed means no sleep"
    );
    assert!(
        sleeps[0] >= Duration::from_millis(199),
        "the first sleep runs to the window's deadline"
    );
}
