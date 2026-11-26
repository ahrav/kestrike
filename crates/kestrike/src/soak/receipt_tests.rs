//! A directory-link swap or a replaced name between refusal and removal can redirect path-resolved cleanup to a
//! file the open did not create.
//!
//! A retained refusal record's name ends in a digest. The alias check finds it and its staging file by prefix and
//! matches each by device and inode: a receipt that names or links one is refused and the record keeps its bytes,
//! and a receipt that is another file beside one opens.

use std::fs;

use super::super::store::tests::{remove, state};
use super::*;

#[test]
fn a_refused_receipt_removes_the_file_it_created_after_its_directory_link_moves() {
    let state = state("receipt-moved-link");
    let store = state.join(STORE_DIR);
    fs::create_dir(&store).unwrap();
    fs::write(state.join("authority"), b"the authority record").unwrap();
    let link = state.join("link");
    std::os::unix::fs::symlink(&store, &link).unwrap();
    let moved = (link.clone(), state.clone());
    BEFORE_REMOVAL.set(Some(Box::new(move || {
        fs::remove_file(&moved.0).unwrap();
        std::os::unix::fs::symlink(&moved.1, &moved.0).unwrap();
    })));

    let refused = open_receipt(&link.join("authority"), &state).unwrap_err();

    assert!(refused.contains("soak-store/authority"), "{refused}");
    assert_eq!(
        fs::read(state.join("authority")).unwrap(),
        b"the authority record",
        "the state directory's record survives the refused open"
    );
    assert!(
        !store.join("authority").exists(),
        "the cleanup removes the file the open created"
    );
    remove(&state);
}

#[test]
fn a_refused_receipt_keeps_a_file_that_replaced_the_one_it_created() {
    let state = state("receipt-replaced");
    let store = state.join(STORE_DIR);
    fs::create_dir(&store).unwrap();
    let receipt = store.join("fresh");
    let replaced = receipt.clone();
    BEFORE_REMOVAL.set(Some(Box::new(move || {
        fs::remove_file(&replaced).unwrap();
        fs::write(&replaced, b"another writer's file").unwrap();
    })));

    let refused = open_receipt(&receipt, &state).unwrap_err();

    assert!(refused.contains("soak-store/fresh"), "{refused}");
    assert!(refused.contains("links another file"), "{refused}");
    assert_eq!(fs::read(&receipt).unwrap(), b"another writer's file");
    remove(&state);
}

/// The name `bind::authority::refusal_name` gives one binding and key incarnation; the name of every retained
/// refusal record starts with `authority-refused-`.
const REFUSAL: &str =
    "authority-refused-72e3efb853a82d9dae7c93ba4a9e299f5b401c038022d432b7ac05e53fb0b280";
const RECORD: &[u8] = b"the retained refusal record";

/// A retained refusal record is a state record, the durable exclusion that later starts of its binding and key
/// incarnation read: a receipt that names it is refused, the refusal names the record, and the refused open leaves
/// the record's bytes.
#[test]
fn a_receipt_naming_a_retained_refusal_record_is_refused_and_the_record_survives() {
    let state = state("receipt-refusal-record");
    let record = state.join(REFUSAL);
    fs::write(&record, RECORD).unwrap();

    let refusal = open_receipt(&record, &state).err();

    let kept = fs::read(&record).unwrap();
    remove(&state);
    assert!(
        refusal.is_some(),
        "the soak refuses a receipt that aliases a retained refusal record"
    );
    let refusal = refusal.unwrap();
    assert!(
        refusal.contains(&format!("{REFUSAL} record")),
        "the refusal names the record: {refusal}"
    );
    assert_eq!(kept, RECORD, "the refused open leaves the record's bytes");
}

#[test]
fn a_receipt_naming_the_record_a_retained_refusal_wrote_is_refused_and_the_record_survives() {
    use crate::bind::authority_tests::{Setup, fresh_records, marker_path};
    use crate::failover::assignment_tests::record;
    use crate::failover::fresh::LocalRecords;
    let setup = Setup::new();
    fresh_records(&setup).retain_refusal(&record()).unwrap();
    let retained = marker_path(&setup, &record());
    let written = fs::read(&retained).unwrap();

    let refusal = open_receipt(&retained, &setup.state).err();

    let kept = fs::read(&retained).unwrap();
    assert!(
        refusal.is_some(),
        "the soak refuses a receipt that names the record a retained refusal wrote"
    );
    assert!(!written.is_empty(), "the writer gave the record its bytes");
    assert_eq!(kept, written, "the refused open leaves the record's bytes");
}

/// The refusal matches a record by device and inode, whatever the receipt's name: a hard link and a symbolic link
/// named `receipt` in another directory, to a retained refusal record or to the atomic writer's staging file of
/// one, are refused as the record's own name is, and each refusal names the file the receipt links.
#[test]
fn a_receipt_linking_a_retained_refusal_record_or_its_staging_file_is_refused() {
    let state = state("receipt-refusal-link");
    let outside = state.with_extension("receipts");
    fs::create_dir(&outside).unwrap();
    let receipt = outside.join("receipt");
    let mut results = Vec::new();
    for name in [REFUSAL.to_owned(), format!("{REFUSAL}.tmp")] {
        let record = state.join(&name);
        for link in ["hard", "symbolic"] {
            fs::write(&record, RECORD).unwrap();
            if link == "hard" {
                fs::hard_link(&record, &receipt).unwrap();
            } else {
                std::os::unix::fs::symlink(&record, &receipt).unwrap();
            }
            let refusal = open_receipt(&receipt, &state).err();
            results.push((link, name.clone(), refusal, fs::read(&record).unwrap()));
            fs::remove_file(&receipt).unwrap();
        }
    }
    fs::remove_dir(&outside).unwrap();
    remove(&state);
    for (link, name, refusal, kept) in results {
        assert!(
            refusal.is_some(),
            "the soak refuses a {link} link to a retained refusal record or its staging file {name}"
        );
        let refusal = refusal.unwrap();
        assert!(
            refusal.contains(&format!("{name} record")),
            "the refusal of a {link} link names {name}: {refusal}"
        );
        assert_eq!(kept, RECORD, "{name} keeps its bytes behind a {link} link");
    }
}

/// The alias check compares the receipt's own file with each retained refusal record: a receipt under another name
/// beside a record is another file, so it opens and the record keeps its bytes.
#[test]
fn a_receipt_beside_a_retained_refusal_record_opens_and_the_record_survives() {
    let state = state("receipt-beside-refusal");
    let record = state.join(REFUSAL);
    fs::write(&record, RECORD).unwrap();

    let refusal = open_receipt(&state.join("receipt"), &state).err();

    let kept = fs::read(&record).unwrap();
    remove(&state);
    assert_eq!(
        refusal, None,
        "the soak opens a receipt that is another file beside a retained refusal record"
    );
    assert_eq!(kept, RECORD, "the open leaves the record's bytes");
}
