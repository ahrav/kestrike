//! The protocol v2 reader over fake segments and scripted clocks: the bracketed body reads, retry and re-evaluation of the cached snapshot, every untrusted cause, the suspend bracket's jitter and resume scripts, and the bound's growth.

use std::collections::VecDeque;

use super::clock::{ClockScale, Reading, Trust, Untrusted};
use super::expiry::NANOS_PER_SECOND;
use super::plant::{Plant, plant};
use super::segment_v2::{
    BODY_LEN, ClockId, HEADER_LEN, Header, Host, MARKER_LEN, Reader, SegmentV2Error, body, header,
};

const REAL: u64 = 1_700_000_000 * NANOS_PER_SECOND;
const MONO: u64 = 100 * NANOS_PER_SECOND;
const MARKER: u64 = 0xD15C;
const BOOT_OFFSET: u64 = 7 * NANOS_PER_SECOND;

/// The segment's fields; `image` lays them out at their protocol offsets.
#[derive(Clone, Copy)]
pub(super) struct Fields {
    version: u16,
    size: u32,
    generation: u16,
    as_of: u64,
    void_after: u64,
    bound: i64,
    marker: u64,
    drift_ppb: u32,
    status: i32,
    support: u8,
}

pub(super) const SYNCED: Fields = Fields {
    version: 2,
    size: 80,
    generation: 4,
    as_of: MONO - NANOS_PER_SECOND,
    void_after: MONO + 10 * NANOS_PER_SECOND,
    bound: 500_000,
    marker: MARKER,
    drift_ppb: 50_000,
    status: 1,
    support: 1,
};

pub(super) fn image(fields: Fields) -> Vec<u8> {
    let mut bytes = vec![0; 80];
    // The daemon writes the magic as the native-endian words 0x414D_5A4E and 0x4342_0200.
    bytes[..8].copy_from_slice(&[0x4E, 0x5A, 0x4D, 0x41, 0x00, 0x02, 0x42, 0x43]);
    bytes[8..12].copy_from_slice(&fields.size.to_le_bytes());
    bytes[12..14].copy_from_slice(&fields.version.to_le_bytes());
    bytes[14..16].copy_from_slice(&fields.generation.to_le_bytes());
    let instant = |bytes: &mut [u8], at: usize, nanos: u64| {
        bytes[at..at + 8].copy_from_slice(&((nanos / NANOS_PER_SECOND) as i64).to_le_bytes());
        bytes[at + 8..at + 16].copy_from_slice(&((nanos % NANOS_PER_SECOND) as i64).to_le_bytes());
    };
    instant(&mut bytes, 16, fields.as_of);
    instant(&mut bytes, 32, fields.void_after);
    bytes[48..56].copy_from_slice(&fields.bound.to_le_bytes());
    bytes[56..64].copy_from_slice(&fields.marker.to_le_bytes());
    bytes[64..68].copy_from_slice(&fields.drift_ppb.to_le_bytes());
    bytes[68..72].copy_from_slice(&fields.status.to_le_bytes());
    bytes[72] = fields.support;
    bytes
}

/// A fake host: each segment read takes the next queued image, or the last one taken, `None` once nothing was ever queued; each clock takes its next queued sample or repeats its last.
#[derive(Default)]
pub(super) struct Fake {
    images: VecDeque<Option<Vec<u8>>>,
    current: Option<Vec<u8>>,
    marker: Option<u64>,
    clocks: [VecDeque<u64>; 3],
    last: [u64; 3],
    segment_reads: usize,
    /// `true` means the reader can observe the segment writer's body stores before its odd generation store.
    unordered: bool,
}

fn slot(clock: ClockId) -> usize {
    match clock {
        ClockId::Realtime => 0,
        ClockId::Monotonic => 1,
        ClockId::Boottime => 2,
    }
}

impl Fake {
    /// A host whose segment holds `fields`, whose marker device holds the matching marker, and whose clocks read `REAL` and `MONO` with a boot offset of exactly `BOOT_OFFSET`, after one first bracket at monotonic `CONSTRUCTED`.
    pub(super) fn holding(fields: Fields) -> Self {
        let mut host = Self {
            current: Some(image(fields)),
            marker: Some(MARKER),
            last: [REAL, MONO, MONO + BOOT_OFFSET],
            ..Self::default()
        };
        host.at(CONSTRUCTED);
        host.at(MONO);
        host
    }

    /// Queues one tight bracket at monotonic `mono` with the unchanged boot offset.
    fn at(&mut self, mono: u64) {
        self.clock_queue(ClockId::Monotonic, &[mono, mono]);
        self.clock_queue(ClockId::Boottime, &[mono + BOOT_OFFSET]);
    }

    /// Queues one image per later segment read.
    pub(super) fn then(&mut self, images: impl IntoIterator<Item = Option<Vec<u8>>>) {
        self.images.extend(images);
    }

    fn clock_queue(&mut self, clock: ClockId, samples: &[u64]) {
        self.clocks[slot(clock)].extend(samples.iter().copied());
    }
}

impl Host for Fake {
    fn segment(&mut self, at: u64, bytes: &mut [u8]) -> Option<usize> {
        self.segment_reads += 1;
        if let Some(next) = self.images.pop_front() {
            self.current = next;
        }
        let image = self.current.as_ref()?;
        let at = at as usize;
        let count = bytes.len().min(image.len().saturating_sub(at));
        bytes[..count].copy_from_slice(&image[at..at + count]);
        Some(count)
    }

    fn marker(&mut self, bytes: &mut [u8]) -> Option<usize> {
        let marker = self.marker?;
        bytes[..4].copy_from_slice(&0x4B4C_4356_u32.to_le_bytes());
        bytes[16..24].copy_from_slice(&marker.to_le_bytes());
        Some(MARKER_LEN)
    }

    fn clock(&mut self, clock: ClockId) -> Option<u64> {
        let at = slot(clock);
        if let Some(sample) = self.clocks[at].pop_front() {
            self.last[at] = sample;
        }
        Some(self.last[at])
    }

    fn writer_stores_ordered(&self) -> bool {
        !self.unordered
    }
}

pub(super) const LIMIT: u64 = 50_000;
/// The monotonic instant of a reader's construction, ten seconds before every snapshot's `as_of`.
const CONSTRUCTED: u64 = MONO - 11 * NANOS_PER_SECOND;

/// A reader built over a segment the daemon wrote before construction, then advanced to `fields`, which the daemon wrote after.
fn reader(fields: Fields) -> Reader<Fake> {
    let mut host = Fake::holding(before_construction(fields));
    host.then([Some(image(fields))]);
    Reader::new(host, ClockScale::UtcSmeared, 3, LIMIT).expect("a valid reader")
}

/// `fields` at generation 2, written one second before construction.
fn before_construction(fields: Fields) -> Fields {
    Fields {
        generation: 2,
        as_of: CONSTRUCTED - NANOS_PER_SECOND,
        ..fields
    }
}

fn cause(reading: Reading) -> Option<Untrusted> {
    match reading.trust {
        Trust::Trusted => None,
        Trust::Untrusted(cause) => Some(cause),
    }
}

/// A synchronized snapshot one second old with a 500 µs bound and 50,000 ppb drift reads `REAL` within 550,000 ns.
#[test]
fn a_synchronized_snapshot_grows_its_bound_from_as_of_by_the_drift() {
    let read = reader(SYNCED).read();
    assert_eq!(
        read,
        Reading {
            earliest: REAL - 550_000,
            latest: REAL + 550_000,
            trust: Trust::Trusted,
        }
    );
    // The growth rounds up: one nanosecond of drift accrues over any part of 20 ns at 50,000,000 ppb.
    let fine = Fields {
        as_of: MONO - 1,
        drift_ppb: 50_000_000,
        ..SYNCED
    };
    assert_eq!(reader(fine).read().latest, REAL + 500_001);
}

#[test]
fn a_free_running_snapshot_is_trusted() {
    let read = reader(Fields {
        status: 2,
        ..SYNCED
    })
    .read();
    assert_eq!(read.trust, Trust::Trusted);
}

/// Unknown, disrupted and unnamed statuses, a stale void-after, disabled disruption support, an absent or mismatched marker and an unsupported version each read untrusted by their own cause.
#[test]
fn each_snapshot_condition_reads_untrusted_by_its_cause() {
    for (fields, expected) in [
        (
            Fields {
                status: 0,
                ..SYNCED
            },
            Untrusted::Unknown,
        ),
        (
            Fields {
                status: 9,
                ..SYNCED
            },
            Untrusted::Unknown,
        ),
        (
            Fields {
                status: 3,
                ..SYNCED
            },
            Untrusted::Disrupted,
        ),
        (
            Fields {
                void_after: MONO - 1,
                ..SYNCED
            },
            Untrusted::Stale,
        ),
        (
            Fields {
                support: 0,
                ..SYNCED
            },
            Untrusted::DisruptionSupportOff,
        ),
        (
            Fields {
                marker: MARKER + 1,
                ..SYNCED
            },
            Untrusted::MarkerMismatch,
        ),
        (
            Fields {
                version: 3,
                ..SYNCED
            },
            Untrusted::Unsupported,
        ),
        (Fields { size: 79, ..SYNCED }, Untrusted::Missing),
        (
            Fields {
                bound: -1,
                ..SYNCED
            },
            Untrusted::Malformed,
        ),
        (
            Fields {
                drift_ppb: 1_000_000_000,
                ..SYNCED
            },
            Untrusted::Malformed,
        ),
    ] {
        assert_eq!(cause(reader(fields).read()), Some(expected));
    }
    // The void-after instant itself is still trusted.
    let edge = Fields {
        void_after: MONO,
        ..SYNCED
    };
    assert_eq!(cause(reader(edge).read()), None);
    let mut absent = reader(SYNCED);
    absent_marker(&mut absent);
    assert_eq!(cause(absent.read()), Some(Untrusted::MarkerUnavailable));
}

fn absent_marker(reader: &mut Reader<Fake>) {
    reader.host_mut().marker = None;
}

/// Planted `TrustDisrupted`: a reader that trusts a disrupted status fails the disruption check by name.
fn disruption_check() -> Result<(), &'static str> {
    match cause(
        reader(Fields {
            status: 3,
            ..SYNCED
        })
        .read(),
    ) {
        Some(Untrusted::Disrupted) => Ok(()),
        None => Err("a disrupted snapshot was trusted"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_disrupted_snapshot_is_untrusted() {
    assert_eq!(disruption_check(), Ok(()));
}

#[test]
fn a_reader_that_trusts_a_disrupted_status_fails_the_disruption_check() {
    let _planted = plant(Plant::TrustDisrupted);
    assert_eq!(disruption_check(), Err("a disrupted snapshot was trusted"));
}

/// A snapshot the daemon wrote before construction shows no writer update since; once the daemon writes again the reading is trusted.
#[test]
fn a_reader_trusts_only_after_a_writer_update_since_construction() {
    let host = Fake::holding(before_construction(SYNCED));
    let mut reader = Reader::new(host, ClockScale::UtcSmeared, 3, LIMIT).unwrap();
    assert_eq!(cause(reader.read()), Some(Untrusted::NoWriterUpdate));
    reader.host_mut().then([Some(image(Fields {
        generation: 6,
        ..SYNCED
    }))]);
    assert_eq!(cause(reader.read()), None);
}

#[test]
fn an_unordered_writer_withholds_trust_after_every_other_cause() {
    let read = |fields| {
        let host = Fake {
            unordered: true,
            ..Fake::holding(fields)
        };
        cause(
            Reader::new(host, ClockScale::UtcSmeared, 3, LIMIT)
                .unwrap()
                .read(),
        )
    };
    assert_eq!(read(SYNCED), Some(Untrusted::UnorderedWriter));
    assert_eq!(
        read(before_construction(SYNCED)),
        Some(Untrusted::NoWriterUpdate)
    );
    assert_eq!(
        read(Fields {
            status: 3,
            ..SYNCED
        }),
        Some(Untrusted::Disrupted)
    );
}

/// Bracketing generations that differ, are odd or are zero refuse the body, so a first read with no snapshot reads untrusted; a short read fails its attempt and, with no snapshot, reads the segment missing.
#[test]
fn a_torn_wiped_or_short_body_fails_its_attempt() {
    let torn = |first: u16, last: u16| {
        [
            Some(image(Fields {
                generation: first,
                ..SYNCED
            })),
            Some(image(SYNCED)),
            Some(image(Fields {
                generation: last,
                ..SYNCED
            })),
        ]
    };
    for (first, last) in [(4, 6), (5, 5), (0, 0)] {
        let mut host = Fake::holding(Fields {
            generation: 1,
            ..SYNCED
        });
        for _ in 0..3 {
            host.then(torn(first, last));
        }
        let mut reader = Reader::new(host, ClockScale::UtcSmeared, 1, LIMIT).unwrap();
        for _ in 0..2 {
            reader.host_mut().then(torn(first, last));
        }
        assert_eq!(cause(reader.read()), Some(Untrusted::NoSnapshot));
    }
    let mut short = Fake::holding(SYNCED);
    short.current = Some(image(SYNCED)[..40].to_vec());
    let mut reader = Reader::new(short, ClockScale::UtcSmeared, 2, LIMIT).unwrap();
    assert_eq!(cause(reader.read()), Some(Untrusted::Missing));
    let mut absent = Fake::holding(SYNCED);
    absent.current = None;
    let mut reader = Reader::new(absent, ClockScale::UtcSmeared, 2, LIMIT).unwrap();
    assert_eq!(cause(reader.read()), Some(Untrusted::Missing));
}

/// An odd generation during a write fails every attempt of the reading, which then re-evaluates the cached snapshot: still trusted while its void-after holds, and stale once it passes.
#[test]
fn odd_generations_retry_then_reevaluate_the_cached_snapshot() {
    let mut reader = reader(SYNCED);
    assert_eq!(cause(reader.read()), None);
    let writing = image(Fields {
        generation: 5,
        ..SYNCED
    });
    let before = reader.host_mut().segment_reads;
    reader
        .host_mut()
        .then((0..9).map(|_| Some(writing.clone())));
    assert_eq!(cause(reader.read()), None);
    // Three attempts of three reads each.
    assert_eq!(reader.host_mut().segment_reads - before, 9);
    reader.host_mut().at(MONO + 10 * NANOS_PER_SECOND + 1);
    assert_eq!(cause(reader.read()), Some(Untrusted::Stale));
}

/// Read jitter between the bracket's three samples widens it without moving the offset's true value, so it stays trusted; a resume moves boot time ahead of monotonic time and reads suspended.
#[test]
fn a_jittered_bracket_stays_trusted_and_a_resume_reads_suspended() {
    let mut reader = reader(SYNCED);
    assert_eq!(cause(reader.read()), None);
    // The reader stalls 20 µs between each pair of samples: m1 = 2 s, b = 2 s + 20 µs + offset, m2 = 2 s + 40 µs.
    let host = reader.host_mut();
    host.clock_queue(
        ClockId::Monotonic,
        &[
            MONO + 2 * NANOS_PER_SECOND,
            MONO + 2 * NANOS_PER_SECOND + 40_000,
        ],
    );
    host.clock_queue(
        ClockId::Boottime,
        &[MONO + 2 * NANOS_PER_SECOND + 20_000 + BOOT_OFFSET],
    );
    assert_eq!(cause(reader.read()), None);
    // A one-second suspend: boot time runs ahead of monotonic time by one more second.
    let host = reader.host_mut();
    host.clock_queue(
        ClockId::Monotonic,
        &[MONO + 3 * NANOS_PER_SECOND, MONO + 3 * NANOS_PER_SECOND],
    );
    host.clock_queue(
        ClockId::Boottime,
        &[MONO + 4 * NANOS_PER_SECOND + BOOT_OFFSET],
    );
    assert_eq!(cause(reader.read()), Some(Untrusted::Suspended));
}

/// A bracket wider than the validated limit fails its attempt; with every bracket that wide the reading has no bounded offset.
#[test]
fn a_bracket_wider_than_its_limit_fails_the_attempt() {
    let mut reader = reader(SYNCED);
    assert_eq!(cause(reader.read()), None);
    let wide = [
        MONO + 5 * NANOS_PER_SECOND,
        MONO + 5 * NANOS_PER_SECOND + LIMIT + 1,
    ];
    let host = reader.host_mut();
    // One wide bracket, then a tight one: the second attempt succeeds.
    host.clock_queue(ClockId::Monotonic, &wide);
    host.clock_queue(
        ClockId::Monotonic,
        &[
            MONO + 6 * NANOS_PER_SECOND,
            MONO + 6 * NANOS_PER_SECOND + LIMIT,
        ],
    );
    host.clock_queue(
        ClockId::Boottime,
        &[
            MONO + 5 * NANOS_PER_SECOND + BOOT_OFFSET,
            MONO + 6 * NANOS_PER_SECOND + BOOT_OFFSET,
        ],
    );
    assert_eq!(cause(reader.read()), None);
    let host = reader.host_mut();
    for _ in 0..4 {
        host.clock_queue(ClockId::Monotonic, &wide);
    }
    assert_eq!(cause(reader.read()), Some(Untrusted::UnboundedBracket));
}

/// With a zero boot offset, as on a host that never suspended, each boot-time sample precedes the bracket's later monotonic sample by the read gap, and the reading stays trusted.
#[test]
fn a_zero_boot_offset_stays_trusted_across_read_gaps() {
    let mut host = Fake {
        current: Some(image(before_construction(SYNCED))),
        marker: Some(MARKER),
        last: [REAL, MONO, MONO],
        ..Fake::default()
    };
    for mono in [CONSTRUCTED, MONO] {
        host.clock_queue(ClockId::Monotonic, &[mono, mono + 40_000]);
        host.clock_queue(ClockId::Boottime, &[mono + 20_000]);
    }
    host.then([Some(image(SYNCED))]);
    let mut reader = Reader::new(host, ClockScale::UtcSmeared, 3, LIMIT).unwrap();
    assert_eq!(cause(reader.read()), None);
    // The shortest suspend these brackets detect: one nanosecond longer than their two 20 µs read gaps.
    let later = MONO + NANOS_PER_SECOND;
    let host = reader.host_mut();
    host.clock_queue(ClockId::Monotonic, &[later, later + 40_000]);
    host.clock_queue(ClockId::Boottime, &[later + 40_001 + 20_000]);
    assert_eq!(cause(reader.read()), Some(Untrusted::Suspended));
}

fn production_reading_of_a_fresh_segment() -> Reading {
    use super::super::os::clock_ticks;
    use super::clock::PhysicalClock;
    use super::segment_v2::SegmentV2;

    let dir = std::env::temp_dir().join(format!("segment-v2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (segment, marker) = (dir.join("shm0"), dir.join("vmclock0"));
    let mut device = [0; MARKER_LEN];
    device[..4].copy_from_slice(&0x4B4C_4356_u32.to_le_bytes());
    device[16..].copy_from_slice(&MARKER.to_le_bytes());
    std::fs::write(&marker, device).unwrap();
    std::fs::write(&segment, image(SYNCED)).unwrap();
    let mut reader = SegmentV2::open(&segment, &marker, ClockScale::UtcSmeared, 3, 100_000_000)
        .expect("a reader on an admitted target");
    let now = clock_ticks(libc::CLOCK_MONOTONIC).unwrap();
    let fresh = Fields {
        as_of: now,
        void_after: now + 100 * NANOS_PER_SECOND,
        ..SYNCED
    };
    std::fs::write(&segment, image(fresh)).unwrap();
    let reading = reader.read();
    std::fs::remove_dir_all(&dir).unwrap();
    reading
}

/// The production reader runs on the host's own clocks, whose boot offset is zero on a host that never suspended.
#[cfg(target_arch = "x86_64")]
#[test]
fn the_production_reader_trusts_a_fresh_segment_on_the_host_clocks() {
    let reading = production_reading_of_a_fresh_segment();
    assert_eq!(reading.trust, Trust::Trusted, "{reading:?}");
}

/// On AArch64 the daemon's release store of its odd generation orders only the accesses before it, so its body stores can reach the reader first.
#[cfg(target_arch = "aarch64")]
#[test]
fn the_production_reader_withholds_trust_from_a_fresh_segment_on_aarch64() {
    assert_eq!(
        cause(production_reading_of_a_fresh_segment()),
        Some(Untrusted::UnorderedWriter)
    );
}

/// A host whose segment and clock device are absent still constructs the production reader, and its first reading is untrusted as `Missing`.
#[test]
fn a_reader_over_absent_files_constructs_and_reads_missing() {
    use super::clock::PhysicalClock;
    use super::segment_v2::SegmentV2;

    let dir = std::env::temp_dir().join(format!("segment-v2-absent-{}", std::process::id()));
    std::fs::create_dir(&dir).expect("a fresh, empty test directory");
    let mut reader = SegmentV2::open(
        &dir.join("shm0"),
        &dir.join("vmclock0"),
        ClockScale::UtcSmeared,
        3,
        100_000_000,
    )
    .expect("a reader on an admitted target");
    let reading = reader.read();
    std::fs::remove_dir(&dir).unwrap();
    assert_eq!(cause(reading), Some(Untrusted::Missing));
}

/// A non-root caller may not open the root-owned `/proc/version` with `O_NOATIME`, so the reader opens it plainly; its kernel-version text layout yields `NoSnapshot`.
#[test]
fn a_segment_opens_without_access_time_permission() {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;

    use super::clock::PhysicalClock;
    use super::segment_v2::SegmentV2;

    let version = Path::new("/proc/version");
    let noatime = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOATIME)
        .open(version);
    if noatime.is_ok() {
        return;
    }
    let mut reader = SegmentV2::open(version, version, ClockScale::UtcSmeared, 2, 100_000_000)
        .expect("a reader on an admitted target");
    assert_eq!(cause(reader.read()), Some(Untrusted::NoSnapshot));
}

#[test]
fn construction_refuses_zero_attempts_and_a_zero_bracket_limit() {
    let refused = |attempts, limit| {
        Reader::new(
            Fake::holding(SYNCED),
            ClockScale::UtcSmeared,
            attempts,
            limit,
        )
        .err()
    };
    assert_eq!(refused(0, LIMIT), Some(SegmentV2Error::ZeroReadAttempts));
    assert_eq!(refused(1, 0), Some(SegmentV2Error::ZeroBracketLimit));
}

/// The pure decoders read every field at its protocol offset: the generation from bytes 14..16 and the body's instants, bound, marker, drift, status and support flag.
#[test]
fn the_decoders_read_each_field_at_its_offset() {
    let bytes = image(SYNCED);
    let mut head = [0; HEADER_LEN];
    head.copy_from_slice(&bytes[..HEADER_LEN]);
    assert_eq!(header(&head), Header::Generation(4));
    let mut payload = [0; BODY_LEN];
    payload.copy_from_slice(&bytes[HEADER_LEN..]);
    let decoded = body(&payload).unwrap();
    assert_eq!(
        (
            decoded.as_of,
            decoded.void_after,
            decoded.bound,
            decoded.marker,
            decoded.drift_ppb,
            decoded.status,
            decoded.disruption_support
        ),
        (
            SYNCED.as_of,
            SYNCED.void_after,
            500_000,
            MARKER,
            50_000,
            1,
            true
        )
    );
    // A nanosecond field of one second or more is not a time value.
    let mut invalid = payload;
    invalid[8..16].copy_from_slice(&(NANOS_PER_SECOND as i64).to_le_bytes());
    assert_eq!(body(&invalid), Err(Untrusted::Malformed));
    // The support flag is 0 or 1; any other byte is outside the protocol.
    let mut flag = payload;
    flag[56] = 2;
    assert_eq!(body(&flag), Err(Untrusted::Malformed));
    flag[56] = 0;
    assert!(!body(&flag).unwrap().disruption_support);
}

/// A suspend after the daemon wrote a generation the reader has not read yet shows in the first bracket after the resume, so that generation reads suspended; the daemon's next write after the resume is trusted.
#[test]
fn a_suspend_before_a_generation_is_first_read_reads_suspended() {
    let mut reader = reader(SYNCED);
    assert_eq!(cause(reader.read()), None);
    // The daemon writes generation 6 at `as_of = MONO + 1 s`, then the host sleeps for an hour.
    let written = Fields {
        generation: 6,
        as_of: MONO + NANOS_PER_SECOND,
        void_after: MONO + 20 * NANOS_PER_SECOND,
        ..SYNCED
    };
    let host = reader.host_mut();
    host.then([Some(image(written))]);
    let resumed = MONO + 2 * NANOS_PER_SECOND;
    host.clock_queue(ClockId::Monotonic, &[resumed, resumed]);
    host.clock_queue(
        ClockId::Boottime,
        &[resumed + BOOT_OFFSET + 3_600 * NANOS_PER_SECOND],
    );
    assert_eq!(cause(reader.read()), Some(Untrusted::Suspended));
    // A later write after the resume, read at the new offset, is trusted again.
    let host = reader.host_mut();
    host.then([Some(image(Fields {
        generation: 8,
        as_of: resumed + NANOS_PER_SECOND,
        void_after: resumed + 20 * NANOS_PER_SECOND,
        ..SYNCED
    }))]);
    let later = resumed + 2 * NANOS_PER_SECOND;
    host.clock_queue(ClockId::Monotonic, &[later, later]);
    host.clock_queue(
        ClockId::Boottime,
        &[later + BOOT_OFFSET + 3_600 * NANOS_PER_SECOND],
    );
    assert_eq!(cause(reader.read()), None);
}

/// A restarted daemon wipes the segment to generation zero and climbs again; a body at a cached generation number replaces the cached one, so its own fields decide the reading.
#[test]
fn a_restarted_daemon_at_a_cached_generation_replaces_the_body() {
    let mut reader = reader(SYNCED);
    assert_eq!(cause(reader.read()), None);
    let wiped = {
        let mut bytes = image(SYNCED);
        bytes[12..16].fill(0);
        bytes[16..].fill(0);
        bytes
    };
    // The wipe carries the magic, version zero and generation zero: every attempt retries and the cached snapshot stays trusted.
    reader.host_mut().then((0..9).map(|_| Some(wiped.clone())));
    assert_eq!(cause(reader.read()), None);
    reader.host_mut().then([Some(image(Fields {
        status: 0,
        ..SYNCED
    }))]);
    assert_eq!(cause(reader.read()), Some(Untrusted::Unknown));
}

/// A short read fails one attempt and a later attempt of the same reading succeeds; a short read beside a cached snapshot re-evaluates the snapshot.
#[test]
fn a_short_read_fails_one_attempt() {
    let mut reader = reader(SYNCED);
    let short = image(SYNCED)[..40].to_vec();
    // The first attempt reads the short file three times, the second the full one.
    let host = reader.host_mut();
    host.images.clear();
    host.then((0..3).map(|_| Some(short.clone())));
    host.then([Some(image(SYNCED))]);
    assert_eq!(cause(reader.read()), None);
    reader.host_mut().then((0..9).map(|_| Some(short.clone())));
    assert_eq!(cause(reader.read()), None);
}

/// A short body read still reads the closing header, so every attempt makes three segment reads: three reads of a 40-byte segment, whose body read is short, then three reads of the full one.
#[test]
fn a_short_body_read_still_reads_the_closing_header() {
    let mut reader = reader(SYNCED);
    let short = image(SYNCED)[..40].to_vec();
    let host = reader.host_mut();
    host.images.clear();
    host.then((0..3).map(|_| Some(short.clone())));
    host.then([Some(image(SYNCED))]);
    let before = reader.host_mut().segment_reads;
    assert_eq!(cause(reader.read()), None);
    assert_eq!(reader.host_mut().segment_reads - before, 6);
}

/// A consistent newer body replaces the cached one even when every bracket of its reading is too wide, so its own status decides.
#[test]
fn a_newer_body_replaces_the_cache_when_its_brackets_fail() {
    let mut reader = reader(SYNCED);
    assert_eq!(cause(reader.read()), None);
    let host = reader.host_mut();
    host.then([Some(image(Fields {
        generation: 6,
        status: 0,
        ..SYNCED
    }))]);
    let wide = [MONO + NANOS_PER_SECOND, MONO + NANOS_PER_SECOND + LIMIT + 1];
    for _ in 0..4 {
        host.clock_queue(ClockId::Monotonic, &wide);
    }
    assert_eq!(cause(reader.read()), Some(Untrusted::UnboundedBracket));
    reader.host_mut().at(MONO + 2 * NANOS_PER_SECOND);
    assert_eq!(cause(reader.read()), Some(Untrusted::Unknown));
}

/// A snapshot adopted under a jittered bracket keeps trusting a later tight bracket at the true offset.
#[test]
fn a_snapshot_adopted_under_jitter_stays_trusted() {
    let mut host = Fake::holding(before_construction(SYNCED));
    host.then([Some(image(SYNCED))]);
    let mut reader = Reader::new(host, ClockScale::UtcSmeared, 3, LIMIT).unwrap();
    let host = reader.host_mut();
    host.clock_queue(ClockId::Monotonic, &[MONO, MONO + 40_000]);
    host.clock_queue(ClockId::Boottime, &[MONO + 20_000 + BOOT_OFFSET]);
    assert_eq!(cause(reader.read()), None);
    reader.host_mut().at(MONO + NANOS_PER_SECOND);
    assert_eq!(cause(reader.read()), None);
}

/// A literal 80-byte segment laid out as the daemon writes it on x86-64 and little-endian AArch64 hosts decodes to its fields: generation 10, `as_of` 12.5 s, `void_after` 1,012.5 s, a 300,000 ns bound, marker 7, 15,000 ppb, synchronized, disruption support on.
#[test]
fn a_golden_daemon_segment_decodes_to_its_fields() {
    #[rustfmt::skip]
    const GOLDEN: [u8; 80] = [
        0x4E, 0x5A, 0x4D, 0x41, 0x00, 0x02, 0x42, 0x43, 0x50, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0A, 0x00,
        0x0C, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x65, 0xCD, 0x1D, 0, 0, 0, 0,
        0xF4, 0x03, 0, 0, 0, 0, 0, 0, 0x00, 0x65, 0xCD, 0x1D, 0, 0, 0, 0,
        0xE0, 0x93, 0x04, 0, 0, 0, 0, 0, 0x07, 0, 0, 0, 0, 0, 0, 0,
        0x98, 0x3A, 0, 0, 0x01, 0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0,
    ];
    let mut head = [0; HEADER_LEN];
    head.copy_from_slice(&GOLDEN[..HEADER_LEN]);
    assert_eq!(header(&head), Header::Generation(10));
    let mut payload = [0; BODY_LEN];
    payload.copy_from_slice(&GOLDEN[HEADER_LEN..]);
    let decoded = body(&payload).unwrap();
    assert_eq!(
        (
            decoded.as_of,
            decoded.void_after,
            decoded.bound,
            decoded.marker
        ),
        (12_500_000_000, 1_012_500_000_000, 300_000, 7)
    );
    assert_eq!(
        (
            decoded.drift_ppb,
            decoded.status,
            decoded.disruption_support
        ),
        (15_000, 1, true)
    );
    // An all-zero file, as a truncated segment shows, is a rewrite and fails the attempt.
    assert_eq!(header(&[0; HEADER_LEN]), Header::Rewriting);
}

/// The big-endian header's magic differs from the little-endian magic, causing `header` to return `Header::Rewriting` even though its generation decodes as the even nonzero value 2,560.
#[test]
fn a_big_endian_daemon_header_reads_as_rewriting() {
    #[rustfmt::skip]
    const BIG_ENDIAN: [u8; HEADER_LEN] = [
        0x41, 0x4D, 0x5A, 0x4E, 0x43, 0x42, 0x02, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x02, 0x00, 0x0A,
    ];
    assert_eq!(header(&BIG_ENDIAN), Header::Rewriting);
}

/// On AArch64, `UnorderedWriter` confirms a daemon update after reader construction because `verdict` checks `NoWriterUpdate` before `UnorderedWriter`.
#[test]
#[ignore = "needs a bounded-clock daemon writing the protocol v2 segment at /var/run/clockbound/shm0 and the hypervisor clock device at /dev/vmclock0"]
fn the_host_daemon_segment_reads_trusted_within_its_bound() {
    use std::path::Path;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use super::clock::PhysicalClock;
    use super::segment_v2::{DEFAULT_MARKER, DEFAULT_SEGMENT, SegmentV2};

    let expected = if cfg!(target_arch = "x86_64") {
        Trust::Trusted
    } else {
        Trust::Untrusted(Untrusted::UnorderedWriter)
    };
    let mut reader = SegmentV2::open(
        Path::new(DEFAULT_SEGMENT),
        Path::new(DEFAULT_MARKER),
        ClockScale::UtcSmeared,
        4,
        1_000_000,
    )
    .expect("a reader on an admitted target");
    let deadline = Instant::now() + Duration::from_secs(30);
    let reading = loop {
        let reading = reader.read();
        eprintln!("clockbound: reading {reading:?}");
        if reading.trust == expected || Instant::now() > deadline {
            break reading;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    assert_eq!(reading.trust, expected, "the daemon updated the segment");
    if expected != Trust::Trusted {
        return;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after the epoch")
        .as_nanos() as u64;
    let width = reading.latest - reading.earliest;
    eprintln!("clockbound: trusted width {width} ns");
    assert!(width <= 10_000_000, "a width of {width} ns");
    // The realtime sample follows the reading, so it may pass the latest bound only by the time between them.
    assert!(
        reading.earliest <= now && now <= reading.latest + 100_000_000,
        "realtime {now} outside [{}, {}]",
        reading.earliest,
        reading.latest
    );
    eprintln!("clockbound: realtime within the bound");
}

/// The module states that the snapshot is the last consistent header and body any attempt read. A body between two
/// equal even generations that the reader refuses, as `Malformed` or under an unsupported version, is such a read, so
/// a later reading whose every attempt is torn re-evaluates no older body: it is untrusted.
///
/// Property: the module documentation of `segment_v2.rs`, "The snapshot is the last consistent header and body any
/// attempt read".
#[test]
fn a_refused_consistent_body_leaves_no_older_snapshot_to_trust() {
    let malformed = image(Fields {
        generation: 6,
        support: 2,
        ..SYNCED
    });
    let unsupported = image(Fields {
        generation: 6,
        version: 3,
        ..SYNCED
    });
    let torn = image(Fields {
        generation: 7,
        ..SYNCED
    });
    let mut trusted = Vec::with_capacity(2);
    for (refused, why) in [
        (malformed, Untrusted::Malformed),
        (unsupported, Untrusted::Unsupported),
    ] {
        let mut reader = reader(SYNCED);
        assert_eq!(
            cause(reader.read()),
            None,
            "premise: generation 4 is trusted"
        );
        reader.host_mut().then([Some(refused)]);
        assert_eq!(
            cause(reader.read()),
            Some(why),
            "premise: generation 6 is read whole and refused"
        );
        reader.host_mut().then([Some(torn.clone())]);
        let reading = reader.read();
        if cause(reading).is_none() {
            trusted.push((why, reading));
        }
    }
    assert!(
        trusted.is_empty(),
        "refused at generation 6, then every attempt torn at generation 7, yet trusted: {trusted:?}"
    );
}
