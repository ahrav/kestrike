use std::cell::Cell;
use std::io;

use super::super::owner_fixture::{Device, narrow};
use super::super::publish_tests::{TRIES, budget, key};
use super::super::volume_fixture::SESSION;
use super::super::writable_tests::reserve;
use super::inspect::AUTHORITY;
use super::vector_tests::{IDENTITY, VECTORS, vector};
use super::{
    Crc32c, Finding, HeaderMismatch, Image, RecordConfig, RecordIdentity, Report, Verdict, Window,
    WindowError, inspect,
};
use crate::bind::RELEASE_SCOPE;

const UNIT: usize = 4096;
const CHUNK: u32 = 4096;

struct Tracked<'a> {
    bytes: &'a [u8],
    lowest: Cell<u64>,
    highest: Cell<u64>,
    /// The longest read, in bytes.
    largest: Cell<usize>,
}

impl<'a> Tracked<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            lowest: Cell::new(u64::MAX),
            highest: Cell::new(0),
            largest: Cell::new(0),
        }
    }
}

impl Image for Tracked<'_> {
    fn read_into(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.lowest.set(self.lowest.get().min(offset));
        self.highest
            .set(self.highest.get().max(offset + buf.len() as u64));
        self.largest.set(self.largest.get().max(buf.len()));
        self.bytes.read_into(buf, offset)
    }
}

fn image() -> (Vec<u8>, Vec<u64>) {
    let mut image = Vec::new();
    let mut offsets = Vec::new();
    for (index, vector) in VECTORS.iter().enumerate() {
        offsets.push(image.len() as u64);
        image.extend_from_slice(vector.bytes);
        image.resize(image.len().next_multiple_of(UNIT), 0);
        if index == 1 {
            image.extend_from_slice(&[0xA5; UNIT]);
        }
    }
    (image, offsets)
}

/// A finished scan: its report, the findings its sink received in order and
/// the lowest and highest image bytes it read.
struct Scan {
    report: Report,
    findings: Vec<Finding>,
    lowest: u64,
    highest: u64,
}

impl Scan {
    /// The text the binary prints after its image line: one line per finding,
    /// then the report.
    fn text(&self) -> String {
        let lines: String = self
            .findings
            .iter()
            .map(|finding| format!("{finding}\n"))
            .collect();
        format!("{lines}{}", self.report)
    }
}

fn collect(findings: &mut Vec<Finding>) -> impl FnMut(Finding) -> io::Result<()> + '_ {
    |finding| {
        findings.push(finding);
        Ok(())
    }
}

fn scan(bytes: &[u8], start: u64, end: u64) -> Scan {
    let config = RecordConfig { chunk_len: CHUNK }.validate().unwrap();
    let tracked = Tracked::new(bytes);
    let window = Window::new(start, end, bytes.len() as u64).unwrap();
    let mut findings = Vec::new();
    let report = inspect(
        &tracked,
        window,
        Crc32c::detect(),
        &config,
        collect(&mut findings),
    )
    .unwrap();
    assert_eq!(report.candidates, findings.len() as u64);
    assert_eq!(
        report.valid,
        findings
            .iter()
            .filter(|finding| finding.verdict == Verdict::Valid)
            .count() as u64
    );
    Scan {
        report,
        findings,
        lowest: tracked.lowest.get(),
        highest: tracked.highest.get(),
    }
}

#[test]
fn the_scan_reports_each_golden_record_with_its_pinned_facts_and_preserves_the_image() {
    let (image, offsets) = image();
    let before = image.clone();
    let scan = scan(&image, 0, image.len() as u64);
    assert_eq!(image, before);
    assert!(scan.lowest == 0 && scan.highest <= image.len() as u64);
    assert_eq!(
        scan.report.units,
        VECTORS.len() as u64 + 1,
        "each record once and the filler unit"
    );
    let expected: Vec<Finding> = VECTORS
        .iter()
        .zip(&offsets)
        .map(|(vector, &offset)| Finding {
            offset,
            verdict: Verdict::Valid,
            identity: Some(IDENTITY),
            lengths: Some((vector.metadata_len, vector.body_len)),
            record_len: Some(vector.bytes.len() as u64),
            header_crc: Some(vector.header_crc),
            chunk_crcs: vector.chunk_crcs.to_vec(),
        })
        .collect();
    assert_eq!(scan.findings, expected);
    assert!(scan.report.verified());
    assert_eq!(
        scan.findings[0].to_string(),
        "record at 0 metadata 0 body 0 len 112 key \
         090000000000000000000000000000000000000000000000000000000000003f slot 4 incarnation 1 \
         session 4294991446 version 7 header-crc 8b968813 chunk-crcs [] valid"
    );
    let mixed = VECTORS.iter().position(|v| v.name == "mixed").unwrap();
    let crcs: Vec<String> = VECTORS[mixed]
        .chunk_crcs
        .iter()
        .map(|crc| format!("{crc:08x}"))
        .collect();
    assert!(crcs.len() > 1);
    let line = scan.findings[mixed].to_string();
    assert!(
        line.ends_with(&format!(" chunk-crcs [{}] valid", crcs.join(" "))),
        "{line}"
    );
}

/// Reads `bytes` until the second read at or past `from`, which fails, so a
/// scan finds the magic at `from` and fails inside that candidate.
struct FailingFrom<'a> {
    bytes: &'a [u8],
    from: u64,
    reached: Cell<bool>,
}

impl Image for FailingFrom<'_> {
    fn read_into(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        if offset >= self.from && self.reached.replace(true) {
            return Err(io::ErrorKind::Other.into());
        }
        self.bytes.read_into(buf, offset)
    }
}

#[test]
fn a_read_error_inside_a_candidate_ends_the_scan_after_the_sink_received_the_earlier_findings() {
    let (image, offsets) = image();
    let config = RecordConfig { chunk_len: CHUNK }.validate().unwrap();
    let failing = FailingFrom {
        bytes: &image,
        from: offsets[1],
        reached: Cell::new(false),
    };
    let window = Window::new(0, image.len() as u64, image.len() as u64).unwrap();
    let mut findings = Vec::new();
    let error = inspect(
        &failing,
        window,
        Crc32c::detect(),
        &config,
        collect(&mut findings),
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Other);
    let received: Vec<_> = findings.iter().map(|f| (f.offset, f.verdict)).collect();
    assert_eq!(received, [(offsets[0], Verdict::Valid)]);
}

#[test]
fn a_sink_error_ends_the_scan_before_it_reads_the_next_unit() {
    let (image, offsets) = image();
    let config = RecordConfig { chunk_len: CHUNK }.validate().unwrap();
    let tracked = Tracked::new(&image);
    let window = Window::new(0, image.len() as u64, image.len() as u64).unwrap();
    let mut received = Vec::new();
    let error = inspect(&tracked, window, Crc32c::detect(), &config, |finding| {
        received.push(finding.offset);
        Err(io::ErrorKind::BrokenPipe.into())
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(received, [offsets[0]]);
    assert!(
        tracked.highest.get() <= offsets[1],
        "no read past the first record"
    );
}

#[test]
fn each_damage_class_is_reported_and_a_damaged_record_hides_no_later_one() {
    let (clean, offsets) = image();
    let mixed = offsets[3] as usize;
    let cases = [
        ("version", mixed + 8, 4),
        ("version one", mixed + 8, 1),
        ("version two", mixed + 8, 2),
        ("forged key", mixed + 16, 0x77),
        ("forged allocation", mixed + 48, 0x77),
        ("forged session", mixed + 56, 0x77),
        ("forged cache version", mixed + 64, 0x77),
        ("magic", mixed, b'X'),
        ("forged body length", mixed + 76, 0x71),
        ("header crc", mixed + 12, 0x00),
        ("later chunk", mixed + UNIT + 100, 0x00),
    ];
    for (name, at, byte) in cases {
        let mut image = clean.clone();
        image[at] = byte;
        assert_ne!(image, clean, "{name} changes a byte");
        let before = image.clone();
        let scan = scan(&image, 0, image.len() as u64);
        assert_eq!(image, before, "{name}");
        assert!(scan.highest <= image.len() as u64);
        assert_eq!(scan.report.verified(), name == "magic", "{name}");
        let found = scan
            .findings
            .iter()
            .find(|finding| finding.offset == offsets[3]);
        let Some(found) = found else {
            assert_eq!(
                name, "magic",
                "only a record without its magic is no candidate"
            );
            assert_eq!(scan.findings.len(), VECTORS.len() - 1);
            continue;
        };
        match (name, found.verdict) {
            ("version", Verdict::Header(HeaderMismatch::Version { found: 4 })) => {}
            ("version one", Verdict::Header(HeaderMismatch::Version { found: 1 })) => {}
            ("version two", Verdict::Header(HeaderMismatch::Version { found: 2 })) => {}
            (
                "forged body length",
                Verdict::Header(HeaderMismatch::ExtentLength {
                    expected: 6065,
                    found: 6064,
                }),
            ) => {}
            (
                "forged key" | "forged allocation" | "forged session" | "forged cache version",
                Verdict::Header(HeaderMismatch::HeaderCrc { stored, .. }),
            ) => {
                assert_eq!(stored, 0x6903_BF0D, "{name}")
            }
            ("header crc", Verdict::Header(HeaderMismatch::HeaderCrc { stored, computed })) => {
                assert_eq!((stored, computed), (0x6903_BF00, 0x6903_BF0D))
            }
            (
                "later chunk",
                Verdict::Chunk {
                    index: 1, stored, ..
                },
            ) => {
                assert_eq!(stored, 0xDC43_050F);
                assert_eq!(found.chunk_crcs, vector("mixed").chunk_crcs);
            }
            (name, verdict) => panic!("{name}: {verdict:?}"),
        }
        assert_eq!(
            found.identity.is_some(),
            name == "later chunk",
            "{name}: identity only from a verified header"
        );
        let later = scan
            .findings
            .iter()
            .find(|finding| finding.offset == offsets[4])
            .unwrap();
        assert_eq!(later.verdict, Verdict::Valid, "{name}: the boundary record");
    }
}

#[test]
fn a_record_inside_a_damaged_record_s_claimed_extent_is_found_one_unit_on() {
    let (mut image, offsets) = image();
    let inner = offsets[3] as usize + UNIT;
    let newer = VECTORS[0].bytes;
    image[inner..inner + newer.len()].copy_from_slice(newer);
    let scan = scan(&image, 0, image.len() as u64);
    assert!(matches!(
        scan.findings[3].verdict,
        Verdict::Chunk { index: 1, .. }
    ));
    assert_eq!(
        (scan.findings[4].offset, scan.findings[4].verdict),
        (inner as u64, Verdict::Valid)
    );
    assert_eq!(
        (scan.findings[5].offset, scan.findings[5].verdict),
        (offsets[4], Verdict::Valid)
    );
    assert_eq!(scan.findings.len(), VECTORS.len() + 1);
}

#[test]
fn a_window_ending_inside_a_record_reports_it_truncated_without_reading_past_the_window() {
    let (image, offsets) = image();
    let mixed = offsets[3];
    let inside_header = mixed + 40;
    let header = scan(&image, mixed, inside_header);
    assert!(header.lowest >= mixed && header.highest <= inside_header);
    assert!(matches!(
        header.findings[0].verdict,
        Verdict::Header(HeaderMismatch::Truncated { len: 40, .. })
    ));
    let inside_payload = mixed + 5000;
    let payload = scan(&image, mixed, inside_payload);
    assert!(payload.lowest >= mixed && payload.highest <= inside_payload);
    let record_len = vector("mixed").bytes.len() as u64;
    assert_eq!(
        payload.findings[0].verdict,
        Verdict::Truncated {
            end: mixed + record_len
        }
    );
    assert_eq!(payload.findings[0].identity, Some(IDENTITY));
}

#[test]
fn the_largest_claimed_lengths_read_at_most_the_window_and_outside_windows_refuse() {
    let mut image = VECTORS[0].bytes.to_vec();
    image.resize(2 * UNIT, 0);
    image[72..76].copy_from_slice(&u32::MAX.to_le_bytes());
    image[76..80].copy_from_slice(&u32::MAX.to_le_bytes());
    let largest = scan(&image, 0, image.len() as u64);
    assert!(largest.highest <= image.len() as u64);
    assert_eq!(
        largest.findings[0].verdict,
        Verdict::Header(HeaderMismatch::Lengths {
            metadata_len: u32::MAX,
            body_len: u32::MAX
        })
    );
    assert_eq!(
        Window::new(10, 9, 100),
        Err(WindowError {
            start: 10,
            end: 9,
            len: 100
        })
    );
    assert!(Window::new(0, 101, 100).is_err());
    assert!(Window::new(u64::MAX, u64::MAX, 100).is_err());
    let unaligned = scan(&image, 1, image.len() as u64);
    assert_eq!(
        unaligned.report.units, 1,
        "the scan starts at the next unit"
    );
    assert_eq!(unaligned.lowest, UNIT as u64);
}

struct Zeros {
    lowest: Cell<u64>,
    reads: Cell<u64>,
    /// The offset whose bytes start with the record magic, if any.
    magic_at: Option<u64>,
}

impl Image for Zeros {
    fn read_into(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        offset.checked_add(buf.len() as u64).unwrap();
        self.lowest.set(self.lowest.get().min(offset));
        self.reads.set(self.reads.get() + 1);
        buf.fill(0);
        if Some(offset) == self.magic_at && buf.len() >= 8 {
            buf[..8].copy_from_slice(b"IMGCREC1");
        }
        Ok(())
    }
}

#[test]
fn a_window_at_the_top_of_the_offset_space_ends_the_scan_without_wrapping() {
    let config = RecordConfig { chunk_len: CHUNK }.validate().unwrap();
    let top = u64::MAX - UNIT as u64 + 1;
    for (start, magic_at, units) in [
        (u64::MAX - 100, None, 0),
        (top - UNIT as u64, None, 2),
        (top - UNIT as u64, Some(top), 2),
    ] {
        let image = Zeros {
            lowest: Cell::new(u64::MAX),
            reads: Cell::new(0),
            magic_at,
        };
        let window = Window::new(start, u64::MAX, u64::MAX).unwrap();
        let mut findings = Vec::new();
        let report = inspect(
            &image,
            window,
            Crc32c::detect(),
            &config,
            collect(&mut findings),
        )
        .unwrap();
        assert_eq!(report.units, units);
        assert!(image.reads.get() == 0 || image.lowest.get() >= start);
        match magic_at {
            None => assert!(findings.is_empty()),
            Some(at) => {
                assert_eq!(findings.len(), 1);
                assert_eq!(findings[0].offset, at);
                assert!(matches!(findings[0].verdict, Verdict::Header(_)));
            }
        }
    }
}

#[test]
fn published_records_are_reported_as_diagnostic_findings_and_the_report_states_both_scopes() {
    let (storage, arena) = narrow(CHUNK, 4, 16384);
    let mut device = Device::new(&storage, &arena);
    let capacity = 1 << 20;
    device.control.write_device(0, &vec![0; capacity]);
    let mut published = Vec::new();
    for (n, name) in [(9, "mixed"), (10, "body")] {
        let fixture = vector(name);
        let mut fill = reserve(
            &storage,
            &key(n),
            fixture.metadata_len as usize,
            fixture.body_len as usize,
        )
        .unwrap();
        device.fill(&mut fill, &fixture.bytes[fixture.header_bytes..]);
        let lease = fill
            .publish(&mut device.volume, u64::MAX, TRIES, &mut budget())
            .unwrap();
        published.push((n, lease, fixture));
    }
    let bytes = device.control.device(0, capacity);
    let before = bytes.clone();
    let scan = scan(&bytes, 0, capacity as u64);
    assert_eq!(bytes, before);
    assert!(scan.findings.is_sorted_by_key(|finding| finding.offset));
    published.sort_by_key(|(_, lease, _)| {
        storage.live_pool().unwrap().records()[lease.id().slot_index()]
            .locator()
            .start_unit()
    });
    assert_eq!(scan.findings.len(), published.len(), "{:#?}", scan.findings);
    for ((n, lease, fixture), finding) in published.iter().zip(&scan.findings) {
        let id = lease.id();
        let locator = storage.live_pool().unwrap().records()[id.slot_index()].locator();
        let offset = super::super::volume_fixture::device_byte(&storage, locator) as u64;
        let at = offset as usize;
        let stored_crc = u32::from_le_bytes(bytes[at + 12..at + 16].try_into().unwrap());
        let identity = RecordIdentity {
            key: key(*n),
            allocation: (id.slot_index() as u64) << 32 | u64::from(id.incarnation()),
            session: SESSION,
            version: 0,
        };
        assert_eq!(finding.offset, offset);
        assert_eq!(finding.verdict, Verdict::Valid);
        assert_eq!(finding.identity, Some(identity));
        assert_eq!(
            finding.lengths,
            Some((fixture.metadata_len, fixture.body_len))
        );
        assert_eq!(finding.header_crc, Some(stored_crc));
        assert_eq!(finding.chunk_crcs, fixture.chunk_crcs);
    }
    let text = scan.text();
    assert!(text.contains(AUTHORITY), "{text}");
    assert!(text.contains(RELEASE_SCOPE), "{text}");
    let findings = text.replace(AUTHORITY, "").replace(RELEASE_SCOPE, "");
    assert!(
        !findings.contains("live") && !findings.contains("recover"),
        "{text}"
    );
    assert_eq!(
        text.lines().filter(|line| line.ends_with(" valid")).count(),
        2
    );
}

#[test]
fn a_replaced_record_left_on_the_device_is_reported_as_valid_bytes_with_its_old_identity() {
    let (storage, arena) = narrow(CHUNK, 4, 16384);
    let mut device = Device::new(&storage, &arena);
    let capacity = 1 << 20;
    device.control.write_device(0, &vec![0; capacity]);
    let mut published = Vec::new();
    for name in ["mixed", "body"] {
        let fixture = vector(name);
        let mut fill = reserve(
            &storage,
            &key(9),
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
        let offset = super::super::volume_fixture::device_byte(&storage, locator) as u64;
        let allocation = (id.slot_index() as u64) << 32 | u64::from(id.incarnation());
        published.push((offset, allocation, fixture));
        drop(lease);
    }
    assert_ne!(
        published[0].0, published[1].0,
        "the replacement lies elsewhere"
    );
    let bytes = device.control.device(0, capacity);
    let scan = scan(&bytes, 0, capacity as u64);
    for (offset, allocation, fixture) in &published {
        let finding = scan
            .findings
            .iter()
            .find(|finding| finding.offset == *offset)
            .unwrap();
        assert_eq!(finding.verdict, Verdict::Valid);
        assert_eq!(
            finding.identity,
            Some(RecordIdentity {
                key: key(9),
                allocation: *allocation,
                session: SESSION,
                version: 0,
            })
        );
        assert_eq!(finding.chunk_crcs, fixture.chunk_crcs);
    }
    let text = scan.text();
    let findings = text.replace(AUTHORITY, "").replace(RELEASE_SCOPE, "");
    assert!(
        !findings.contains("live") && !findings.contains("recover"),
        "{text}"
    );
}
