//! A reader whose session superseded the session that wrote a record gets a header mismatch and none of its
//! bytes. A session is a tenure `g * 2^32 + a`, and the read predicate (`record::predicate::accepts`) refuses a
//! record whose session has another shard generation than the reader's, so a reader of a later generation gets
//! `HeaderMismatch::ForeignSession` and no byte of a record an earlier generation wrote.
//!
//! Each test writes one object's record through the production fill path (`WritableFill::receive` and
//! `publish` over the simulated device), reads the slot's extent from the device media, and reads the record
//! for the same index entry as a reader of another session: the header through `record::verify_header` and
//! the payload through `Storage::record_payload`, the lens the observer reads bound records with. The
//! publication, a hit, the session change and the delivery with the outcome that read returned are then
//! written as oracle rows, and `oracle::check` judges them. The object's payload is the oracle's content for
//! its label, so the first test also judges the delivery the read withheld: the whole payload with outcome
//! `Complete`. After the session change that delivery fails with the rule "a delivery of content from a
//! superseded session"; omitting the session-change row makes the same delivery pass.
//!
//! The first test reads as the next shard generation, at the writer's epoch and at a later one, so the
//! generation is the only check that refuses. The second is its control: a reader of the writer's own
//! generation at a later epoch, the warm takeover, reads the exact bytes, and so does the writer's session.
//!
//! The observations are decided into values, the fixtures are dropped, and only then does a test assert.

use super::CacheVersion;
use super::budget::WorkBudget;
use super::config::StorageConfig;
use super::layout::IO_UNIT;
use super::owner::Storage;
use super::publish_tests::{PAGE, TRIES, index_config, key, storage_config, storage_from};
use super::record::{
    Crc32c, ExpectedHeader, ExtentPosition, HeaderMismatch, RecordIdentity, verify_header,
};
use super::test_platform::TestPlatform;
use super::volume_fixture::{Device, arena_with};
use super::writable_tests::reserve_at;
use crate::index::IndexConfig;
use crate::oracle::{Failure, KeyId, Label, Obligation, Outcome, Recorder, Script, Verdict, check};

const VERSION: u64 = 0x000B_1EC7;
const METADATA_LEN: usize = 4;
const BODY_LEN: usize = 150;

/// The oracle's key and label of the one object.
const KEY: KeyId = KeyId(0);
const LABEL: Label = Label(10);

/// A storage of eight slots with two fill records.
fn storage() -> Storage<TestPlatform> {
    let fills = [2];
    let index = IndexConfig {
        fills: &fills,
        ..index_config(&[8], (1, 1), 1)
    };
    let config = StorageConfig {
        lease_limit: 16,
        ..storage_config(8)
    };
    let storage = storage_from(&config, &index, TestPlatform::heap(PAGE));
    storage.platform.ticks(&[Some(1)]);
    storage
}

/// What one reader's read of the record returned.
#[derive(Debug, PartialEq, Eq)]
struct Read {
    reader: u64,
    /// The header check's refusal, `None` when the header verified.
    header: Option<HeaderMismatch>,
    /// The metadata length and payload the lens delivered, `None` when it delivered nothing.
    delivered: Option<(u32, Vec<u8>)>,
}

/// The record's writer session, its payload, and what each reader read.
struct Observed {
    written: u64,
    payload: Vec<u8>,
    reads: Vec<Read>,
}

/// Publishes one object through the production fill path, then reads its record from the device media as a
/// reader of each session `readers` derives from the writer's.
fn observe(readers: impl Fn(u64) -> Vec<u64>) -> Observed {
    let storage = storage();
    let buffers = arena_with(4, 5);
    let _ = crate::storage::next_session();
    let mut dev = Device::new(&storage, &buffers);
    let payload = Recorder::content(KEY, LABEL, METADATA_LEN as u32, BODY_LEN as u64);
    let object = key(9);
    let mut fill = reserve_at(
        &storage,
        &object,
        CacheVersion(VERSION),
        METADATA_LEN,
        BODY_LEN,
    )
    .expect("a reservation");
    dev.fill(&mut fill, &payload);
    let lease = fill
        .publish(
            &mut dev.volume,
            u64::MAX,
            TRIES,
            &mut WorkBudget::new(1 << 20),
        )
        .expect("published");
    let slot = lease.id().slot_index();
    let allocation = lease.id().record_tag();
    let written = dev.volume.session();
    let mut facts = Vec::new();
    storage.slot_facts_into(&mut facts).expect("live");
    let fact = &facts[slot];
    let mut media = Vec::new();
    let range = fact.media().expect("the slot's extent lies on the device");
    let read_media = dev.control.try_device_into(range, &mut media);
    let named = RecordIdentity {
        key: object,
        allocation,
        session: fact.session,
        version: fact.version,
    };
    let reads = readers(written)
        .into_iter()
        .map(|reader| {
            let expected = ExpectedHeader {
                identity: named,
                reader,
                position: ExtentPosition::FIRST,
                len_units: (media.len() / IO_UNIT) as u32,
                lengths: None,
            };
            let header = verify_header(Crc32c::detect(), &storage.record, &media, &expected).err();
            let delivered = storage
                .record_payload(&media, allocation, fact, reader)
                .map(|(_, metadata, bytes)| (metadata, bytes.to_vec()));
            Read {
                reader,
                header,
                delivered,
            }
        })
        .collect();
    let observed = Observed {
        written: if read_media && named.session == written {
            written
        } else {
            0
        },
        payload,
        reads,
    };
    drop(lease);
    observed
}

/// Records a session change to `session` in `script`. The oracle's session id type is private to the
/// oracle, so its value comes from a delivery row of a probe script and is then set to `session`.
fn change_session(script: &mut Script, session: u64) {
    let mut probe = Script::new();
    let read = probe.lookup(KEY, Outcome::Hit, Some(LABEL));
    probe.deliver_sized(read, KEY, LABEL, (0, 0), Outcome::Complete, Vec::new());
    let history = probe.finish();
    let mut id = history
        .rows()
        .iter()
        .find_map(|row| row.session)
        .expect("a delivery row names a session");
    id.0 = session;
    script.session_change(id);
}

/// The oracle's verdict on the publication, a hit, a session change to the reader's session when
/// `superseding`, and the delivery `read` returned: complete with the delivered bytes, or a header mismatch
/// with none.
fn judged(read: &Read, superseding: bool) -> Verdict {
    let lengths = (METADATA_LEN as u32, BODY_LEN as u64);
    let mut script = Script::new();
    script.publish_sized(KEY, LABEL, lengths.0, lengths.1);
    let hit = script.lookup(KEY, Outcome::Hit, Some(LABEL));
    if superseding {
        change_session(&mut script, read.reader);
    }
    let (outcome, bytes) = match &read.delivered {
        Some((_, bytes)) => (Outcome::Complete, bytes.clone()),
        None => (Outcome::Damaged(Failure::HeaderMismatch), Vec::new()),
    };
    script.deliver_sized(hit, KEY, LABEL, lengths, outcome, bytes);
    check(&script.finish())
}

#[test]
fn a_later_generation_reads_no_byte_of_an_earlier_generation_s_record() {
    let next_generation = |written: u64| vec![written + (1 << 32), written + (1 << 32) + 2];
    let observed = observe(next_generation);
    let verdicts: Vec<Verdict> = observed
        .reads
        .iter()
        .map(|read| judged(read, true))
        .collect();
    assert_ne!(
        observed.written, 0,
        "the slot names the writer's session and its media was read"
    );
    assert_eq!(observed.reads.len(), 2);
    for (read, verdict) in observed.reads.iter().zip(&verdicts) {
        assert_eq!(read.reader >> 32, (observed.written >> 32) + 1);
        let withheld = Read {
            reader: read.reader,
            header: None,
            delivered: Some((METADATA_LEN as u32, observed.payload.clone())),
        };
        assert_eq!(
            judged(&withheld, true).violated(),
            Some((
                Obligation::Bytes,
                "a delivery of content from a superseded session"
            )),
            "reader {:#x}: the whole payload delivered after the session change",
            read.reader
        );
        let unchanged = judged(&withheld, false);
        assert!(
            unchanged.satisfies(&[Obligation::Bytes]),
            "reader {:#x}: the whole payload delivered with no session change: {unchanged:?}",
            read.reader
        );
        assert!(
            verdict.satisfies(&[Obligation::Contain]),
            "reader {:#x} of a later generation: {verdict:?}; the read returned {read:?}",
            read.reader
        );
        assert_eq!(
            read.header,
            Some(HeaderMismatch::ForeignSession {
                found: observed.written,
                reader: read.reader,
            }),
            "reader {:#x}",
            read.reader
        );
        assert_eq!(read.delivered, None, "reader {:#x}", read.reader);
    }
}

#[test]
fn a_later_epoch_of_the_writer_s_generation_reads_the_record() {
    let same_generation = |written: u64| vec![written, written + 2];
    let observed = observe(same_generation);
    assert_ne!(
        observed.written, 0,
        "the slot names the writer's session and its media was read"
    );
    assert_eq!(observed.reads.len(), 2);
    for read in &observed.reads {
        assert_eq!(read.reader >> 32, observed.written >> 32);
        assert_eq!(read.header, None, "reader {:#x}", read.reader);
        assert_eq!(
            read.delivered,
            Some((METADATA_LEN as u32, observed.payload.clone())),
            "reader {:#x}",
            read.reader
        );
    }
}
