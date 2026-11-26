use super::*;

/// Every path of a job follows its id's first two characters, and a name
/// shorter than two characters is its own shard.
#[test]
fn paths_follow_the_shard_of_the_job_id() {
    let id = "ab".to_owned() + &"0".repeat(62);
    assert_eq!(shard(&id).as_str(), "ab");
    assert_eq!(shard("x").as_str(), "x");
    assert_eq!(
        job_file(&id, &format!("{id}.json")),
        PathBuf::from(format!("jobs/ab/{id}.json"))
    );
    assert_eq!(
        attempt_path(&id, 7),
        PathBuf::from(format!("attempts/ab/{id}/0007"))
    );
}

/// A root entry that is not two lowercase hex digits, or that does not open
/// as a directory, is a foreign item of the iteration, and the shards beside
/// it still open in name order.
#[test]
fn entries_that_are_not_shards_are_foreign_items() {
    let case = crate::store::fixture::Case::new();
    let store = Store::open(&case.state).unwrap();
    for entry in ["0f", "abc", "zz", "AB", "e9"] {
        std::fs::create_dir_all(case.state.join(JOBS).join(entry)).unwrap();
    }
    std::fs::write(case.state.join(JOBS).join("1a"), b"stray").unwrap();
    std::os::unix::fs::symlink(&case.state, case.state.join(JOBS).join("2b")).unwrap();
    let items: Vec<_> = shards(&store, JOBS)
        .unwrap()
        .map(|item| match item {
            Ok(shard) => Ok(shard.path),
            Err(Error::Foreign(path)) => Err(path),
            Err(error) => panic!("{error:?}"),
        })
        .collect();
    assert_eq!(
        items,
        [
            Ok("jobs/0f".to_owned()),
            Err("jobs/1a".to_owned()),
            Err("jobs/2b".to_owned()),
            Err("jobs/AB".to_owned()),
            Err("jobs/abc".to_owned()),
            Ok("jobs/e9".to_owned()),
            Err("jobs/zz".to_owned()),
        ]
    );
    assert_eq!(shards(&store, ATTEMPTS).unwrap().count(), 0);
}

/// A host fault on a shard's open is that item's error, so no caller reads
/// a shard it could not open as a foreign entry.
#[test]
fn a_host_fault_opening_a_shard_is_the_items_error() {
    use crate::step::{self, Outcome, Script, Step};
    let case = crate::store::fixture::Case::new();
    let store = Store::open(&case.state).unwrap();
    std::fs::create_dir_all(case.state.join(JOBS).join("0f")).unwrap();
    let mut items = shards(&store, JOBS).unwrap();
    step::install(Some(Script {
        nth: Some((Step::Open, 0, Outcome::Errno(libc::EIO))),
        ..Script::default()
    }));
    let item = items.next().unwrap();
    step::install(None);
    assert!(
        matches!(&item, Err(Error::Unreadable(error)) if error.faulted()),
        "{:?}",
        item.map(|shard| shard.path)
    );
}
