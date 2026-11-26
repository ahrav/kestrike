//! A finding of the read-only scan is an observation of bytes. A record that verifies is reported valid with
//! the identity it names; whether it is live or recoverable needs the recovery owner's separate authority.
//!
//! The scenario publishes an object on the simulated device and then a second object under the same key, so
//! the first record is replaced while its extent still lies on the device, and scans the device's bytes. The
//! finding at the old record's offset is `Valid` and names the old record's slot and incarnation, read from
//! the first lease's id, with the key, session and cache version its header holds; the replacement's finding
//! names its own allocation word, and the report counts both valid. The sibling publishes the first object
//! alone: its one finding carries the same verdict and the identity of its lease.
//!
//! Each test reads the leases' ids, the offsets and the scan into values, lets the device and the storage go,
//! and asserts afterwards.

use std::io;

use super::super::owner_fixture::{Device, narrow};
use super::super::publish_tests::{TRIES, budget, key};
use super::super::volume_fixture::{SESSION, device_byte};
use super::super::writable_tests::reserve;
use super::vector_tests::vector;
use super::{Crc32c, Finding, RecordConfig, RecordIdentity, Report, Verdict, Window, inspect};

const CHUNK: u32 = 4096;
const CAPACITY: usize = 1 << 20;
/// The key both objects are published under.
const KEY: u8 = 9;

/// One publication as its lease named it: where its record starts on the device, its slot and its
/// incarnation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Published {
    offset: u64,
    slot: u64,
    incarnation: u32,
}

impl Published {
    /// The allocation word a header of this publication holds: the slot above the incarnation.
    fn allocation(self) -> u64 {
        self.slot << 32 | u64::from(self.incarnation)
    }

    fn identity(self) -> RecordIdentity {
        RecordIdentity {
            key: key(KEY),
            allocation: self.allocation(),
            session: SESSION,
            version: 0,
        }
    }
}

/// What a scan of the whole device saw after the publications of `names`, each under [`KEY`], each lease
/// dropped before the next publication.
struct Observed {
    published: Vec<Published>,
    report: Report,
    findings: Vec<Finding>,
}

impl Observed {
    fn at(&self, offset: u64) -> Option<&Finding> {
        self.findings
            .iter()
            .find(|finding| finding.offset == offset)
    }

    /// The verdict and identity of the finding at `offset`.
    fn reported(&self, offset: u64) -> Option<(Verdict, Option<RecordIdentity>)> {
        self.at(offset)
            .map(|finding| (finding.verdict, finding.identity))
    }
}

fn observe(names: &[&str]) -> Observed {
    let (storage, arena) = narrow(CHUNK, 4, 16384);
    let mut device = Device::new(&storage, &arena);
    device.control.write_device(0, &vec![0; CAPACITY]);
    let mut published = Vec::new();
    for name in names {
        let fixture = vector(name);
        let mut fill = reserve(
            &storage,
            &key(KEY),
            fixture.metadata_len as usize,
            fixture.body_len as usize,
        )
        .unwrap();
        device.fill(&mut fill, &fixture.bytes[fixture.header_bytes..]);
        let lease = fill
            .publish(&mut device.volume, u64::MAX, TRIES, &mut budget())
            .unwrap();
        let id = lease.id();
        let locator = storage.live_pool().unwrap().records()[id.slot_index()].locator();
        published.push(Published {
            offset: device_byte(&storage, locator) as u64,
            slot: id.slot_index() as u64,
            incarnation: id.incarnation(),
        });
        drop(lease);
    }
    let bytes = device.control.device(0, CAPACITY);
    drop(device);
    let config = RecordConfig { chunk_len: CHUNK }.validate().unwrap();
    let window = Window::new(0, CAPACITY as u64, bytes.len() as u64).unwrap();
    let mut findings = Vec::new();
    let report = inspect(
        &bytes[..],
        window,
        Crc32c::detect(),
        &config,
        |finding| -> io::Result<()> {
            findings.push(finding);
            Ok(())
        },
    )
    .unwrap();
    Observed {
        published,
        report,
        findings,
    }
}

/// The replaced record's bytes still verify, and the scan reports them `Valid` under the old record's own
/// slot and incarnation; the replacement is reported under its own allocation word, and both count as valid.
/// The scan names what the bytes hold and says nothing of which record is live.
#[test]
fn a_replaced_record_on_the_device_is_reported_valid_with_its_old_slot_and_incarnation() {
    let observed = observe(&["mixed", "body"]);
    let (old, new) = (observed.published[0], observed.published[1]);
    let old_reported = observed.reported(old.offset);
    let new_reported = observed.reported(new.offset);
    let old_text = observed.at(old.offset).map(Finding::to_string);
    let counts = (observed.report.candidates, observed.report.valid);

    assert_ne!(
        old.incarnation, 0,
        "premise: a claimed slot's incarnation is not zero"
    );
    assert_ne!(
        old.offset, new.offset,
        "premise: the replacement lies elsewhere, so the old record's extent is still on the device"
    );
    assert_ne!(
        old.allocation(),
        new.allocation(),
        "premise: the replacement has another allocation word"
    );
    assert_eq!(
        old_reported,
        Some((Verdict::Valid, Some(old.identity()))),
        "the replaced record is reported valid with the slot and incarnation its bytes name"
    );
    let named = format!(" slot {} incarnation {} ", old.slot, old.incarnation);
    assert!(
        old_text
            .as_deref()
            .is_some_and(|text| text.contains(&named)),
        "the finding's text names the old slot and incarnation: {old_text:?}"
    );
    assert_eq!(
        new_reported,
        Some((Verdict::Valid, Some(new.identity()))),
        "the replacement is reported valid with its own allocation word"
    );
    assert_eq!(counts, (2, 2), "the report counts both records as valid");
}

/// The sibling without the replacement: the first object alone is reported `Valid` with the identity of its
/// lease, the one candidate of the scan.
#[test]
fn a_record_that_was_not_replaced_is_reported_valid_with_its_lease_s_identity() {
    let observed = observe(&["mixed"]);
    let only = observed.published[0];
    let reported = observed.reported(only.offset);
    let counts = (observed.report.candidates, observed.report.valid);

    assert_ne!(
        only.incarnation, 0,
        "premise: a claimed slot's incarnation is not zero"
    );
    assert_eq!(
        reported,
        Some((Verdict::Valid, Some(only.identity()))),
        "the live record is reported valid with the slot and incarnation its bytes name"
    );
    assert_eq!(counts, (1, 1), "the report counts the one record as valid");
}
