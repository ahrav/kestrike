use std::fs;

use super::codec::encode;
use super::identity_tests::{PINNED_KEYS, pinned};
use super::{BOUND, Held, Job, Record, Text};
use crate::exit::Supervisor;
use crate::store::fixture::{Case, name, snapshot};
use crate::store::{Creation, Error, Refusal, Store, Unreadable};

#[test]
fn typed_replacement_checks_the_bound_before_mutation() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    store
        .create_record(store.root(), &name("job"), &job())
        .unwrap();
    let before = snapshot(&case.state);
    assert!(matches!(
        store.replace_record(store.root(), &name("job"), &sized(BOUND as usize)),
        Err(Error::Oversize)
    ));
    assert_eq!(snapshot(&case.state), before);
    let changed = sized(4);
    store
        .replace_record(store.root(), &name("job"), &changed)
        .unwrap();
    let found = store
        .read_record::<Job>(store.root(), &name("job"))
        .unwrap()
        .unwrap();
    assert_eq!(found.record(), &changed);
    assert_eq!(found.read().bytes().len(), changed.encoded_len());
}

#[test]
fn typed_record_writes_raise_the_soft_file_limit_before_mutation() {
    const CHILD: &str = "CAMPAIGN_TYPED_RECORD_FILE_LIMIT_TEST";
    if std::env::var_os(CHILD).is_some() {
        let case = Case::new();
        let store = Store::open(&case.state).unwrap();
        let entry = name("job");
        crate::sys::restrict_file_limit(1, 65536).unwrap();
        store.create_record(store.root(), &entry, &job()).unwrap();
        let changed = sized(4);
        crate::sys::restrict_file_limit(1, 65536).unwrap();
        store
            .replace_record(store.root(), &entry, &changed)
            .unwrap();
        let found = store
            .read_record::<Job>(store.root(), &entry)
            .unwrap()
            .unwrap();
        assert_eq!(found.record(), &changed);
        return;
    }
    let _processes = crate::store::fixture::processes();
    use std::os::unix::process::CommandExt;
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "record::stored_tests::typed_record_writes_raise_the_soft_file_limit_before_mutation",
        ])
        .process_group(0)
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{:?}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("test result: ok. 1 passed; 0 failed; 0 ignored;")
    );
}

fn job() -> Job {
    Job::derive(pinned(), &PINNED_KEYS)
        .expect("the keys fit the experiment")
        .0
}

/// The pinned job with a campaign of `len` bytes.
fn sized(len: usize) -> Job {
    let mut experiment = pinned();
    experiment.campaign = Text::new(&"c".repeat(len)).expect("the text is ASCII");
    Job::derive(experiment, &PINNED_KEYS)
        .expect("the keys fit the experiment")
        .0
}

/// A created record reads back verified and equal, its file holds exactly
/// its canonical bytes, and a second create of the same job or of another
/// job under its name leaves the store unchanged.
#[test]
fn a_written_record_reads_back_verified() {
    let case = Case::new();
    let store = Store::open(&case.state).expect("the store opens");
    let jobs = name("jobs");
    store
        .mkdir(store.root(), &jobs)
        .expect("the directory is made");
    let dir = store
        .open_dir(store.root(), &jobs)
        .expect("the directory opens")
        .expect("the directory exists");
    let record = name(&job().id().to_string());
    assert_eq!(
        store
            .create_record(&dir, &record, &job())
            .expect("the record is written"),
        Creation::Created
    );
    let path = case.state.join("jobs").join(record.as_str());
    assert_eq!(fs::read(&path).expect("the file reads"), encode(&job()));
    let verified = store
        .read_record::<Job>(&dir, &record)
        .expect("the record verifies")
        .expect("the record exists");
    assert_eq!(verified.record(), &job());
    store
        .barrier(verified.read())
        .expect("the record is made durable");
    assert!(matches!(
        store.read_record::<Job>(&dir, &name("absent")),
        Ok(None)
    ));
    let mut other = pinned();
    other.run = 1;
    let (other, _) = Job::derive(other, &PINNED_KEYS).expect("the keys fit the experiment");
    let before = snapshot(&case.state);
    for again in [job(), other] {
        assert_eq!(
            store
                .create_record(&dir, &record, &again)
                .expect("the create runs"),
            Creation::Existing
        );
        assert_eq!(snapshot(&case.state), before);
    }
}

/// A damaged record is held, a create over its name keeps the damaged
/// bytes, and it stays held.
#[test]
fn a_held_record_is_never_replaced() {
    let case = Case::new();
    let store = Store::open(&case.state).expect("the store opens");
    let record = name("job");
    let mut damaged = encode(&job());
    let last = damaged.len() - 3;
    damaged[last] = if damaged[last] == b'0' { b'1' } else { b'0' };
    store
        .create_once(store.root(), &record, &damaged)
        .expect("the damaged bytes are written");
    let held = store
        .read_record::<Job>(store.root(), &record)
        .expect_err("the damaged record is held");
    assert!(matches!(held, Held::Checksum), "{held:?}");
    assert_eq!(held.exit(), Supervisor::Held);
    assert_eq!(
        store
            .create_record(store.root(), &record, &job())
            .expect("the create runs"),
        Creation::Existing
    );
    assert_eq!(
        fs::read(case.state.join("job")).expect("the file reads"),
        damaged
    );
    assert!(matches!(
        store.read_record::<Job>(store.root(), &record),
        Err(Held::Checksum)
    ));
}

/// A record larger than the reader's bound is refused before any write and
/// leaves the store writable; a file past the bound reads as unreadable.
#[test]
fn an_oversized_record_is_never_written() {
    let case = Case::new();
    let store = Store::open(&case.state).expect("the store opens");
    let big = sized(BOUND as usize);
    let before = snapshot(&case.state);
    let refused = store.create_record(store.root(), &name("big"), &big);
    assert!(matches!(refused, Err(Error::Oversize)), "{refused:?}");
    assert_eq!(
        refused.expect_err("the record is refused").exit(),
        Supervisor::Rejected
    );
    assert_eq!(snapshot(&case.state), before);
    assert_eq!(
        store
            .create_record(store.root(), &name("job"), &job())
            .expect("the store stays writable"),
        Creation::Created
    );
    fs::write(case.state.join("over"), vec![b' '; BOUND as usize + 1])
        .expect("the file is written");
    assert!(matches!(
        store.read_record::<Job>(store.root(), &name("over")),
        Err(Held::Unreadable(Unreadable::Oversize))
    ));
}

/// A poisoned store refuses a record as poisoned before measuring it, so
/// an oversized record on a poisoned store exits as held.
#[test]
fn a_poisoned_store_refuses_a_record_before_its_size() {
    let case = Case::new();
    let store = Store::open(&case.state).expect("the store opens");
    let big = sized(BOUND as usize);
    let moved = case.root.join("moved");
    fs::rename(&case.state, &moved).expect("the state directory moves");
    let replaced = store.create_record(store.root(), &name("job"), &job());
    assert!(matches!(replaced, Err(Error::Replaced)), "{replaced:?}");
    fs::rename(&moved, &case.state).expect("the state directory moves back");
    let refused = store.create_record(store.root(), &name("big"), &big);
    assert!(matches!(refused, Err(Error::Poisoned)), "{refused:?}");
    assert_eq!(
        refused.expect_err("the record is refused").exit(),
        Supervisor::Held
    );
}

/// A record headed for another store's directory panics before it is
/// measured, as every store mutation does.
#[test]
#[should_panic(expected = "a store uses only its own directory handles")]
fn a_record_for_another_stores_directory_panics() {
    let (first, second) = (Case::new(), Case::new());
    let store = Store::open(&first.state).expect("the store opens");
    let other = Store::open(&second.state).expect("the other store opens");
    let big = sized(BOUND as usize);
    let _ = store.create_record(other.root(), &name("big"), &big);
}

/// The record bound is 1 MiB, a stored-format constant that every reader
/// of existing state shares. A record whose encoding is exactly the bound
/// is written and reads back verified, and one byte more is refused before
/// any write, so the writer and the reader agree on the bound.
#[test]
fn the_writer_and_the_reader_share_one_bound() {
    let case = Case::new();
    let store = Store::open(&case.state).expect("the store opens");
    assert_eq!(BOUND, 1 << 20);
    // The seed's decimal width depends on the campaign, so the length
    // converges within a few steps.
    let mut len = BOUND as usize - 400;
    for _ in 0..8 {
        let encoded = encode(&sized(len)).len();
        if encoded == BOUND as usize {
            break;
        }
        len = len + BOUND as usize - encoded;
    }
    let exact = sized(len);
    assert_eq!(encode(&exact).len(), BOUND as usize);
    assert_eq!(
        store
            .create_record(store.root(), &name("exact"), &exact)
            .expect("a record at the bound is written"),
        Creation::Created
    );
    let verified = store
        .read_record::<Job>(store.root(), &name("exact"))
        .expect("a record at the bound verifies")
        .expect("the record exists");
    assert_eq!(verified.record(), &exact);
    let over = (1..=40)
        .map(|extra| sized(len + extra))
        .find(|job| encode(job).len() == BOUND as usize + 1)
        .expect("one more campaign byte gives one more encoded byte");
    let before = snapshot(&case.state);
    assert!(matches!(
        store.create_record(store.root(), &name("over"), &over),
        Err(Error::Oversize)
    ));
    assert_eq!(snapshot(&case.state), before);
}

/// A directory that holds a job record but no state marker is refused
/// unchanged, and a staged file never lists as a record.
#[test]
fn an_unmarked_directory_with_records_is_refused() {
    let case = Case::new();
    let store = Store::open(&case.state).expect("the store opens");
    store
        .create_record(store.root(), &name("job"), &job())
        .expect("the record is written");
    fs::write(case.state.join(".staging").join("job"), b"staged")
        .expect("a staged file is planted");
    assert_eq!(
        store.list(store.root(), 8).expect("the directory lists"),
        [name("job")]
    );
    drop(store);
    fs::remove_file(case.state.join(".state")).expect("the marker is removed");
    let before = snapshot(&case.state);
    let refused = Store::open(&case.state);
    assert!(
        matches!(refused, Err(Error::Refused(Refusal::Unmarked))),
        "{refused:?}"
    );
    assert_eq!(snapshot(&case.state), before);
}
