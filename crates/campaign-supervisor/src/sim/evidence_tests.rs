//! Literal bundle records pin the first failure, semantic indexes and partial reads.

use super::evidence::{difference, first_failure};
use crate::exit::Sim;
use crate::record::Digest;
use crate::store::fixture::Case;
use std::fs;

fn bundle(body: &[[u8; 48]]) -> Vec<u8> {
    let manifest =
        b"build = b\nexecutable = e\nplatform = p\ntoolchain = t\nrecords = 1000\nbytes = 48000\n";
    let mut bytes = vec![0; 48];
    bytes[0] = 1;
    for (at, chunk) in manifest.chunks(43).enumerate() {
        let mut record = [0; 48];
        record[0] = 2;
        record[1] = 1;
        record[2..4].copy_from_slice(&(at as u16).to_le_bytes());
        record[4] = chunk.len() as u8;
        record[5..5 + chunk.len()].copy_from_slice(chunk);
        bytes.extend_from_slice(&record);
    }
    for record in body {
        bytes.extend_from_slice(record);
    }
    bytes
}
#[test]
fn the_first_failure_keeps_its_index_clock_and_raw_record() {
    let case = Case::new();
    let path = case.state.join("bundle");
    let mut clock = [0; 48];
    clock[0] = 5;
    clock[4..12].copy_from_slice(&734u64.to_le_bytes());
    let mut first = [0; 48];
    first[0] = 7;
    first[4] = 0xaa;
    first[47] = 0xcc;
    let mut second = first;
    second[4] = 0xbb;
    let mut diagnostic = [0; 48];
    diagnostic[0] = 10;
    let mut choice = [0; 48];
    choice[0] = 3;
    let mut event = [0; 48];
    event[0] = 6;
    let mut terminal = [0; 48];
    terminal[0] = 8;
    fs::write(
        &path,
        bundle(&[clock, diagnostic, choice, event, first, second, terminal]),
    )
    .expect("fixture");
    let failure = first_failure(&path, Digest::of(&fs::read(&path).expect("bytes")))
        .expect("scan")
        .expect("first failure");
    assert_eq!(failure.semantic_record, 6);
    assert_eq!(failure.virtual_us, Some(734));
    assert!(failure.node.is_none() && failure.operation.is_none());
    assert_eq!(
        failure.record.as_str(),
        "07000000aa000000000000000000000000000000000000000000000000000000000000000000000000000000000000cc"
    );
}
#[test]
fn semantic_comparison_skips_diagnostics_and_marks_a_shorter_stream() {
    let case = Case::new();
    let left = case.state.join("left");
    let right = case.state.join("right");
    let mut turn = [0; 48];
    turn[0] = 4;
    let mut skipped = [0; 48];
    skipped[0] = 9;
    fs::write(&left, bundle(&[turn, skipped])).expect("left");
    fs::write(&right, bundle(&[turn])).expect("right");
    assert!(
        difference(
            &left,
            &right,
            Digest::of(&fs::read(&left).expect("left")),
            Digest::of(&fs::read(&right).expect("right"))
        )
        .expect("scan")
        .is_none()
    );
    fs::write(&right, bundle(&[])).expect("shorter");
    let diff = difference(
        &left,
        &right,
        Digest::of(&fs::read(&left).expect("left")),
        Digest::of(&fs::read(&right).expect("right")),
    )
    .expect("scan")
    .expect("difference");
    // The TURN follows Begin and two manifest chunks; CHECKPOINT stays outside the comparison.
    assert_eq!(diff.committed.expect("left event").semantic_record, 3);
    assert!(diff.replayed.is_none());
}
#[test]
fn a_partial_raw_record_is_incomplete_evidence() {
    let case = Case::new();
    let path = case.state.join("partial");
    let mut raw = bundle(&[]);
    raw.push(7);
    fs::write(&path, raw).expect("partial fixture");
    assert_eq!(
        first_failure(&path, Digest::of(&fs::read(&path).expect("bytes")))
            .expect_err("partial record")
            .0,
        Sim::Incomplete
    );
}

#[test]
fn unknown_record_tags_refuse_semantic_evidence() {
    let case = Case::new();
    let path = case.state.join("unknown");
    for tag in [0, 11, 255] {
        let mut record = [0; 48];
        record[0] = tag;
        let raw = bundle(&[record]);
        fs::write(&path, &raw).expect("fixture");
        let refused = first_failure(&path, Digest::of(&raw)).expect_err("unknown tag");
        assert_eq!(refused.0, Sim::Incomplete);
        assert!(refused.1.contains("unknown record tag"));
    }
}

#[test]
fn terminal_records_participate_in_semantic_comparison() {
    let case = Case::new();
    let left = case.state.join("left");
    let right = case.state.join("right");
    let mut terminal = [0; 48];
    terminal[0] = 8;
    let original = bundle(&[terminal]);
    terminal[47] = 1;
    let observed = bundle(&[terminal]);
    fs::write(&left, &original).expect("left");
    fs::write(&right, &observed).expect("right");
    let diff = difference(&left, &right, Digest::of(&original), Digest::of(&observed))
        .expect("scan")
        .expect("terminal difference");
    assert_eq!(diff.committed.expect("original").semantic_record, 3);
    assert_eq!(diff.replayed.expect("observed").semantic_record, 3);
}

#[test]
fn semantic_scans_are_bound_to_the_frozen_digest() {
    let case = Case::new();
    let path = case.state.join("digest");
    fs::write(&path, bundle(&[])).expect("fixture");
    assert_eq!(
        first_failure(&path, Digest::of(b"another input"))
            .expect_err("changed digest")
            .0,
        Sim::Incomplete
    );
}
#[test]
fn a_frozen_bundle_read_fault_is_reported_as_unreadable_rather_than_changed() {
    use super::evidence::Frozen;
    use crate::step::{Outcome, Step};
    use crate::store::fixture::scripted;
    let case = Case::new();
    let path = case.state.join("frozen.bundle");
    let bytes = bundle(&[]);
    fs::write(&path, &bytes).expect("fixture");
    let frozen = Frozen::bundle(path.clone(), Digest::of(&bytes)).expect("admitted");
    let (checked, reached) = scripted(None, || frozen.check());
    checked
        .expect("script")
        .expect("the unchanged bundle passes its check");
    let read = reached
        .iter()
        .position(|step| *step == Step::Read)
        .expect("the check reads the bundle");
    let (faulted, _) = scripted([(read, Outcome::Errno(libc::EIO))], || frozen.check());
    let stop = faulted
        .expect("script")
        .expect_err("a faulted read fails the check");
    assert_eq!(stop.0, Sim::Incomplete);
    assert!(
        stop.1.contains("cannot be read after admission") && !stop.1.contains("changed"),
        "{}",
        stop.1
    );
    assert!(stop.1.contains(path.to_str().expect("UTF-8")), "{}", stop.1);
    let reopen = reached
        .iter()
        .rposition(|step| *step == Step::Open)
        .expect("the check reopens the bundle");
    assert!(reopen > read, "the closing reopen follows the read");
    let (faulted, _) = scripted([(reopen, Outcome::Errno(libc::EIO))], || frozen.check());
    let stop = faulted
        .expect("script")
        .expect_err("a faulted reopen fails the check");
    assert_eq!(stop.0, Sim::Incomplete);
    assert!(
        stop.1.contains("cannot be read after admission") && !stop.1.contains("changed"),
        "{}",
        stop.1
    );
}
#[test]
fn a_read_fault_inside_a_semantic_scan_names_the_path_and_the_fault() {
    use crate::step::{Outcome, Step};
    use crate::store::fixture::scripted;
    let case = Case::new();
    let path = case.state.join("scanned.bundle");
    let mut body = [[0; 48]; 200];
    for (at, record) in body.iter_mut().enumerate() {
        record[0] = 1 + (at % 8) as u8;
    }
    let bytes = bundle(&body);
    fs::write(&path, &bytes).expect("fixture");
    let digest = Digest::of(&bytes);
    let (clean, reached) = scripted(None, || first_failure(&path, digest));
    clean.expect("script").expect("the unchanged bundle scans");
    let reads: Vec<usize> = reached
        .iter()
        .enumerate()
        .filter(|(_, step)| **step == Step::Read)
        .map(|(at, _)| at)
        .collect();
    assert!(reads.len() >= 3, "{reached:?}");
    let inside = reads[reads.len() - 2];
    let (faulted, _) = scripted([(inside, Outcome::Errno(libc::EIO))], || {
        first_failure(&path, digest)
    });
    let stop = faulted
        .expect("script")
        .expect_err("a faulted scan read fails");
    assert_eq!(stop.0, Sim::Incomplete);
    assert!(stop.1.contains(path.to_str().expect("UTF-8")), "{}", stop.1);
    assert!(
        stop.1
            .contains(&std::io::Error::from_raw_os_error(libc::EIO).to_string()),
        "{}",
        stop.1
    );
}
