//! The volume's physical clock on the publication path: the pair `bind` stores from one reading and one later sample, absent pairs counted by cause while live behavior stays the same, untrusted and refused publications persisting no row, the report's trust state and last-trusted age, the clock contract, attach's scale check and charge, and the writer's planted controls.

use std::sync::atomic::Ordering;

use super::super::lookup_tests::lookup;
use super::super::owner::Storage;
use super::super::portable::plant::{Plant, plant};
use super::super::portable::scripted::{ClockScript, ScriptedClock, TEST_EARLIEST};
use super::super::portable::{
    Absent, ClockContract, ClockScale, Malformed, PhysicalClock, PortableExpiry, Reading,
    SegmentV2, Trust, Untrusted,
};
use super::super::publication_tests::filled;
use super::super::publish_tests::{RETRIES, TRIES, budget, key};
use super::super::test_platform::TestPlatform;
use super::super::volume_fixture::{DEPTH, Device, TICK, arena_with, device_with};
use super::super::{EngineBudget, LookupError, TEST_CLOCK};
use super::attach::Volume;
use super::config::AttachError;
use super::journal_tests::storage_with;

const SECOND: u64 = 1_000_000_000;
/// The monotonic sample every publication here takes after its reading.
const NOW: u64 = 5 * SECOND;
/// A live deadline ten seconds after `NOW`.
const LIVE: u64 = NOW + 10 * SECOND;

fn trusted(earliest: u64, latest: u64) -> Reading {
    Reading {
        earliest,
        latest,
        trust: Trust::Trusted,
    }
}

/// A storage of eight slots under `contract`, its clock sampling `NOW`.
fn storage(contract: ClockContract) -> Storage<TestPlatform> {
    let storage = storage_with(|volume| {
        volume.clock = contract;
    });
    storage.platform.ticks(&[Some(NOW)]);
    storage
}

/// A device over `storage` reading a fresh script, and the script.
fn scripted<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    buffers: &'a super::super::BufferArena<TestPlatform>,
) -> (Device<'s, 'a>, ClockScript) {
    let (clock, script) = ScriptedClock::with_script();
    (Device::clocked(storage, buffers, clock), script)
}

/// Publishes `n`'s object with live deadline `deadline`, drops its lease and services its row; returns the pair its slot holds.
fn publish_at<'s>(
    storage: &'s Storage<TestPlatform>,
    dev: &mut Device<'s, '_>,
    n: u8,
    deadline: u64,
) -> PortableExpiry {
    let fill = filled(storage, dev, &key(n), &[n; 20]);
    let lease = fill
        .publish(&mut dev.volume, deadline, TRIES, &mut budget())
        .unwrap();
    pair_of(storage, lease)
}

/// Each absent cause is counted once per publication and leaves the slot's pair absent: an untrusted reading, a width one nanosecond past the maximum, a zero earliest bound, a failed sample, a passed live deadline and an overflowing sum.
#[test]
fn each_absent_cause_counts_once_and_binds_the_absent_pair() {
    let storage = storage(TEST_CLOCK);
    let buffers = arena_with(4, 5);
    let (mut dev, script) = scripted(&storage, &buffers);
    let max = TEST_CLOCK.max_uncertainty_ns;
    let cases: [(Reading, Option<u64>, u64, Absent); 6] = [
        (
            Reading::untrusted(Untrusted::Stale),
            Some(NOW),
            LIVE,
            Absent::Untrusted,
        ),
        (
            trusted(TEST_EARLIEST, TEST_EARLIEST + max + 1),
            Some(NOW),
            LIVE,
            Absent::WidthExceeded,
        ),
        (trusted(0, 1), Some(NOW), LIVE, Absent::EarliestZero),
        (
            trusted(TEST_EARLIEST, TEST_EARLIEST),
            None,
            LIVE,
            Absent::MonotonicUnavailable,
        ),
        (
            trusted(TEST_EARLIEST, TEST_EARLIEST),
            Some(LIVE),
            LIVE,
            Absent::LiveDeadlinePassed,
        ),
        (
            trusted(u64::MAX - 1, u64::MAX - 1),
            Some(NOW),
            LIVE,
            Absent::Overflow,
        ),
    ];
    // The sample of the reading the volume holds from the case before.
    let mut held: Option<u64> = None;
    for (n, (reading, sample, deadline, cause)) in (1u8..).zip(cases) {
        script.queue(&[reading]);
        // A held reading's sample reads a millisecond old, so each case reads its own reading; then the portable sample, then the publisher's in-hold sample, which a publication needs to succeed.
        let aged = held.map(|at| Some(at + 1_000_000));
        let ticks: Vec<Option<u64>> = aged.into_iter().chain([sample, Some(NOW)]).collect();
        storage.platform.ticks(&ticks);
        let expiry = publish_at(&storage, &mut dev, n, deadline);
        assert_eq!(expiry, PortableExpiry::ABSENT, "{cause:?}");
        let absent = dev.volume.report().clock.absent;
        assert_eq!(
            (absent.of(cause), absent.total()),
            (1, u64::from(n)),
            "{cause:?}"
        );
        held = sample;
    }
}

/// A volume whose production reader finds no segment publishes the absent pair, reports the segment missing, counts one untrusted cause, and serves until its monotonic deadline.
#[test]
fn a_reader_over_absent_files_publishes_absent_pairs_and_lives_as_before() {
    let dir = std::env::temp_dir().join(format!("volume-clock-absent-{}", std::process::id()));
    std::fs::create_dir(&dir).expect("a fresh, empty test directory");
    let clock = SegmentV2::open(
        &dir.join("shm0"),
        &dir.join("vmclock0"),
        TEST_CLOCK.scale,
        3,
        100_000_000,
    )
    .expect("a reader on an admitted target");
    std::fs::remove_dir(&dir).unwrap();
    let storage = storage(TEST_CLOCK);
    let buffers = arena_with(4, 5);
    let mut dev = Device::clocked(&storage, &buffers, Box::new(clock));
    assert_eq!(
        publish_at(&storage, &mut dev, 1, LIVE),
        PortableExpiry::ABSENT
    );
    let report = dev.volume.report().clock;
    assert_eq!(report.trust, Some(Trust::Untrusted(Untrusted::Missing)));
    assert_eq!(
        (report.absent.of(Absent::Untrusted), report.absent.total()),
        (1, 1)
    );
    let mut reader = storage.register().unwrap();
    storage.platform.ticks(&[Some(LIVE - 1)]);
    drop(lookup(&mut reader, &key(1), RETRIES).expect("a hit below the deadline"));
    storage.platform.ticks(&[Some(LIVE)]);
    assert_eq!(
        lookup(&mut reader, &key(1), RETRIES).err(),
        Some(LookupError::Expired),
        "expired at the deadline"
    );
}

/// A publication under an untrusted reading publishes, serves and expires on its monotonic deadline as a trusted one does, and counts its absent pair.
#[test]
fn an_untrusted_publication_lives_as_before_and_counts_its_absent_pair() {
    for clock in [ScriptedClock::untrusted(), ScriptedClock::trusted()] {
        let storage = storage(TEST_CLOCK);
        let buffers = arena_with(4, 5);
        let mut dev = Device::clocked(&storage, &buffers, clock);
        publish_at(&storage, &mut dev, 1, LIVE);
        let mut reader = storage.register().unwrap();
        storage.platform.ticks(&[Some(LIVE - 1)]);
        drop(lookup(&mut reader, &key(1), RETRIES).expect("a hit below the deadline"));
        storage.platform.ticks(&[Some(LIVE)]);
        assert_eq!(
            lookup(&mut reader, &key(1), RETRIES).err(),
            Some(LookupError::Expired),
            "expired at the deadline"
        );
    }
    let storage = storage(TEST_CLOCK);
    let buffers = arena_with(4, 5);
    let mut dev = Device::clocked(&storage, &buffers, ScriptedClock::untrusted());
    publish_at(&storage, &mut dev, 1, LIVE);
    let report = dev.volume.report().clock;
    assert_eq!(report.trust, Some(Trust::Untrusted(Untrusted::NoSnapshot)));
    assert_eq!(
        report.absent.of(super::super::portable::Absent::Untrusted),
        1
    );
}

/// A publication refused after `bind` holds a present pair on its retired slot and counts no absent pair.
#[test]
fn a_publication_refused_after_bind_keeps_its_present_pair() {
    let storage = storage(TEST_CLOCK);
    let buffers = arena_with(4, 5);
    let (mut dev, script) = scripted(&storage, &buffers);
    script.trusted(TEST_EARLIEST, TEST_EARLIEST);
    let fill = filled(&storage, &mut dev, &key(1), &[1; 20]);
    // The portable sample succeeds and the publisher's in-hold sample fails.
    storage.platform.ticks(&[Some(NOW), None]);
    assert_eq!(
        fill.publish(&mut dev.volume, LIVE, TRIES, &mut budget())
            .err(),
        Some(super::super::FillPublishError::ClockUnavailable)
    );
    storage.platform.ticks(&[Some(NOW)]);
    assert_eq!(dev.volume.report().clock.absent.total(), 0);
    // The refused slot retired with the present pair its bind stored.
    let held = |storage: &Storage<TestPlatform>| {
        let pool = storage.live_pool().unwrap();
        let mut access = pool.try_lock().unwrap();
        let present = (0..8)
            .filter(|&slot| access.tables().expiry(slot).deadline_ns != 0)
            .count();
        access.release();
        present
    };
    assert_eq!(held(&storage), 1);
}

/// An extent's return clears its slot's pair with its key.
#[test]
fn a_returned_extent_clears_the_pair() {
    let storage = storage(TEST_CLOCK);
    let buffers = arena_with(4, 5);
    let (mut dev, script) = scripted(&storage, &buffers);
    script.trusted(TEST_EARLIEST, TEST_EARLIEST);
    let fill = filled(&storage, &mut dev, &key(1), &[1; 20]);
    let lease = fill
        .publish(&mut dev.volume, LIVE, TRIES, &mut budget())
        .unwrap();
    let slot = lease.id().slot_index();
    drop(lease);
    super::super::publication_tests::drain(&storage);
    super::super::attempt_tests::invalidate(&storage, &key(1)).unwrap();
    dev.persist_journal();
    super::super::publication_tests::drain(&storage);
    let pool = storage.live_pool().unwrap();
    let mut access = pool.try_lock().unwrap();
    assert_eq!(
        access.tables().state.ledger.resident + access.tables().state.ledger.retired,
        0,
        "the extent returned"
    );
    assert_eq!(access.tables().expiry(slot), PortableExpiry::ABSENT);
    access.release();
}

/// Reading the report takes no monotonic sample: the samples a test queues stay for the publications under test, and the PUT path's per-chunk counter reads pay for no clock read.
#[test]
fn the_report_takes_no_monotonic_sample() {
    let storage = storage(TEST_CLOCK);
    let buffers = arena_with(4, 5);
    let (dev, _script) = scripted(&storage, &buffers);
    storage.platform.ticks(&[Some(NOW)]);
    let taken = storage.platform.samples_taken();
    let first = dev.volume.report();
    let second = dev.volume.report();
    assert_eq!(storage.platform.samples_taken(), taken);
    assert_eq!(first, second);
}

/// The report names an untrusted provider's cause and keeps the sample after its last trusted reading; a trusted reading moves that sample.
#[test]
fn the_report_shows_trust_and_the_last_trusted_sample_a_trusted_reading_moves() {
    let storage = storage(TEST_CLOCK);
    let buffers = arena_with(4, 5);
    let (mut dev, script) = scripted(&storage, &buffers);
    let report = dev.volume.report().clock;
    assert_eq!((report.trust, report.last_trusted_at), (None, None));
    script.trusted(TEST_EARLIEST, TEST_EARLIEST);
    storage.platform.ticks(&[Some(NOW), Some(NOW)]);
    publish_at(&storage, &mut dev, 1, LIVE);
    let report = dev.volume.report().clock;
    assert_eq!(
        (report.trust, report.last_trusted_at),
        (Some(Trust::Trusted), Some(NOW))
    );
    script.queue(&[Reading::untrusted(Untrusted::Suspended)]);
    storage
        .platform
        .ticks(&[Some(NOW + 2 * SECOND), Some(NOW + 2 * SECOND)]);
    publish_at(&storage, &mut dev, 2, LIVE);
    let report = dev.volume.report().clock;
    assert_eq!(
        (report.trust, report.last_trusted_at),
        (Some(Trust::Untrusted(Untrusted::Suspended)), Some(NOW))
    );
    script.trusted(TEST_EARLIEST, TEST_EARLIEST);
    storage
        .platform
        .ticks(&[Some(NOW + 5 * SECOND), Some(NOW + 5 * SECOND)]);
    publish_at(&storage, &mut dev, 3, LIVE + 5 * SECOND);
    let report = dev.volume.report().clock;
    assert_eq!(
        (report.trust, report.last_trusted_at),
        (Some(Trust::Trusted), Some(NOW + 5 * SECOND))
    );
}

/// The pair the slot of `lease`'s object holds, once its lease is dropped and its row serviced.
pub(super) fn pair_of<'s>(
    storage: &'s Storage<TestPlatform>,
    lease: super::super::ExtentLease<'s, TestPlatform>,
) -> PortableExpiry {
    let slot = lease.id().slot_index();
    drop(lease);
    storage
        .service_fills(crate::index::ShardIndex(0), 4, &mut budget())
        .unwrap();
    let pool = storage.live_pool().unwrap();
    let mut access = pool.try_lock().unwrap();
    let expiry = access.tables().expiry(slot);
    access.release();
    expiry
}

/// Publications made less than a millisecond of the monotonic clock after a reading's sample convert from that reading and sample: they read no provider, and each pair is the reading's earliest bound plus its own deadline's lifetime from the shared sample. The publication made a millisecond after the sample reads the provider again.
#[test]
fn publications_within_a_millisecond_of_a_sample_share_its_reading() {
    const MILLISECOND: u64 = 1_000_000;
    let storage = storage(TEST_CLOCK);
    let buffers = arena_with(4, 5);
    let (mut dev, script) = scripted(&storage, &buffers);
    script.observe(|| 0);
    script.trusted(TEST_EARLIEST, TEST_EARLIEST);
    script.trusted(TEST_EARLIEST + SECOND, TEST_EARLIEST + SECOND);
    let first = filled(&storage, &mut dev, &key(1), &[1; 20]);
    let second = filled(&storage, &mut dev, &key(2), &[2; 20]);
    let first = first
        .publish(&mut dev.volume, LIVE, TRIES, &mut budget())
        .unwrap();
    let second = second
        .publish(&mut dev.volume, LIVE + 5 * SECOND, TRIES, &mut budget())
        .unwrap();
    assert_eq!(script.observed().len(), 1, "one reading for both");
    assert_eq!(
        pair_of(&storage, first),
        PortableExpiry {
            deadline_ns: TEST_EARLIEST + 10 * SECOND,
            lifetime_ms: 10_000,
        }
    );
    assert_eq!(
        pair_of(&storage, second),
        PortableExpiry {
            deadline_ns: TEST_EARLIEST + 15 * SECOND,
            lifetime_ms: 15_000,
        }
    );
    storage.platform.ticks(&[Some(NOW + MILLISECOND - 1)]);
    let third = filled(&storage, &mut dev, &key(3), &[3; 20]);
    let third = third
        .publish(&mut dev.volume, LIVE, TRIES, &mut budget())
        .unwrap();
    assert_eq!(
        script.observed().len(),
        1,
        "a publication under a millisecond after the sample shares the reading"
    );
    assert_eq!(
        pair_of(&storage, third),
        PortableExpiry {
            deadline_ns: TEST_EARLIEST + 10 * SECOND,
            lifetime_ms: 10_000,
        }
    );
    storage.platform.ticks(&[Some(NOW + MILLISECOND)]);
    let fourth = filled(&storage, &mut dev, &key(4), &[4; 20]);
    let fourth = fourth
        .publish(&mut dev.volume, LIVE, TRIES, &mut budget())
        .unwrap();
    assert_eq!(
        script.observed().len(),
        2,
        "a publication a millisecond after the sample reads the provider"
    );
    let fourth = pair_of(&storage, fourth);
    assert_eq!(fourth.lifetime_ms, 9_999);
    assert_eq!(
        fourth.deadline_ns,
        TEST_EARLIEST + SECOND + 9_999 * MILLISECOND
    );
}

/// A reading that converts to no pair serves the publications of its millisecond as a reading that converts does: the publication made under a millisecond after the sample reads no provider and counts its own absent pair, and the publication made a millisecond after the sample reads the provider again.
#[test]
fn an_untrusted_reading_serves_its_millisecond_and_the_next_reads_the_provider() {
    const MILLISECOND: u64 = 1_000_000;
    let storage = storage(TEST_CLOCK);
    let buffers = arena_with(4, 5);
    let (mut dev, script) = scripted(&storage, &buffers);
    script.observe(|| 0);
    script.queue(&[Reading::untrusted(Untrusted::Stale)]);
    script.trusted(TEST_EARLIEST, TEST_EARLIEST);
    let first = filled(&storage, &mut dev, &key(1), &[1; 20]);
    let first = first
        .publish(&mut dev.volume, LIVE, TRIES, &mut budget())
        .unwrap();
    assert_eq!(pair_of(&storage, first), PortableExpiry::ABSENT);
    storage.platform.ticks(&[Some(NOW + MILLISECOND - 1)]);
    let second = filled(&storage, &mut dev, &key(2), &[2; 20]);
    let second = second
        .publish(&mut dev.volume, LIVE, TRIES, &mut budget())
        .unwrap();
    assert_eq!(
        script.observed().len(),
        1,
        "a publication under a millisecond after the sample shares the untrusted reading"
    );
    assert_eq!(pair_of(&storage, second), PortableExpiry::ABSENT);
    let report = dev.volume.report().clock;
    assert_eq!(
        (report.absent.of(Absent::Untrusted), report.absent.total()),
        (2, 2),
        "each publication counts its own absent pair"
    );
    assert_eq!(
        report.trust,
        Some(Trust::Untrusted(Untrusted::Stale)),
        "the report keeps the shared reading's verdict"
    );
    storage.platform.ticks(&[Some(NOW + MILLISECOND)]);
    let third = filled(&storage, &mut dev, &key(3), &[3; 20]);
    let third = third
        .publish(&mut dev.volume, LIVE, TRIES, &mut budget())
        .unwrap();
    assert_eq!(
        script.observed().len(),
        2,
        "a publication a millisecond after the sample reads the provider"
    );
    let third = pair_of(&storage, third);
    assert_eq!(third.lifetime_ms, 9_999);
    assert_eq!(third.deadline_ns, TEST_EARLIEST + 9_999 * MILLISECOND);
    assert_eq!(dev.volume.report().clock.absent.total(), 2);
}

/// A live deadline that is not a whole second converts from the slot's rounded-down deadline, and one at `u64::MAX` shortens to the `u32::MAX` millisecond cap.
#[test]
fn the_pair_converts_from_the_slot_deadline_and_caps_the_lifetime() {
    let storage = storage(TEST_CLOCK);
    let buffers = arena_with(4, 5);
    let (mut dev, script) = scripted(&storage, &buffers);
    script.trusted(TEST_EARLIEST, TEST_EARLIEST);
    assert_eq!(
        publish_at(&storage, &mut dev, 1, LIVE + SECOND - 1),
        PortableExpiry {
            deadline_ns: TEST_EARLIEST + 10 * SECOND,
            lifetime_ms: 10_000,
        }
    );
    assert_eq!(clamp(&storage, &mut dev, 2), Ok(()));
}

/// Publishes `n`'s object at the `u64::MAX` live deadline and checks the captured pair: the lifetime cap with the deadline at earliest plus the cap.
fn clamp<'s>(
    storage: &'s Storage<TestPlatform>,
    dev: &mut Device<'s, '_>,
    n: u8,
) -> Result<(), &'static str> {
    let pair = publish_at(storage, dev, n, u64::MAX);
    if pair.lifetime_ms != u32::MAX {
        panic!("{pair:?}");
    }
    if pair.deadline_ns - u64::from(u32::MAX) * 1_000_000 != TEST_EARLIEST {
        return Err("the lifetime cap persisted as never expiring");
    }
    Ok(())
}

/// Planted `ClampAsNever`: a capped lifetime persisted as a deadline that never expires fails the cap check by name.
#[test]
fn a_capped_lifetime_persisted_as_never_fails_the_cap_check() {
    let storage = storage(TEST_CLOCK);
    let buffers = arena_with(4, 5);
    let (mut dev, script) = scripted(&storage, &buffers);
    script.trusted(TEST_EARLIEST, TEST_EARLIEST);
    let _planted = plant(Plant::ClampAsNever);
    assert_eq!(
        clamp(&storage, &mut dev, 1),
        Err("the lifetime cap persisted as never expiring")
    );
}

/// Publishes under a contract of 100 ppm writer rate error and checks the stored lifetime against the remaining life through that bound.
fn rate_margin() -> Result<(), &'static str> {
    let storage = storage(ClockContract {
        rate_error_ppb: 100_000,
        ..TEST_CLOCK
    });
    let buffers = arena_with(4, 5);
    let (mut dev, script) = scripted(&storage, &buffers);
    script.trusted(TEST_EARLIEST, TEST_EARLIEST);
    let pair = publish_at(&storage, &mut dev, 1, LIVE);
    let stretched = u128::from(pair.lifetime_ms) * 1_000_000 * (1_000_000_000 + 100_000);
    if stretched > u128::from(LIVE - NOW) * 1_000_000_000 {
        return Err("a portable deadline outlives the live deadline through the rate bound");
    }
    assert_eq!(pair.lifetime_ms, 9_999);
    Ok(())
}

#[test]
fn a_rate_error_shortens_the_stored_lifetime() {
    assert_eq!(rate_margin(), Ok(()));
}

/// Planted `IgnoreRateBound`: a conversion with no rate margin stores ten whole seconds, which outlive the live deadline on a writer running 100 ppm fast.
#[test]
fn a_conversion_that_ignores_the_rate_bound_fails_the_margin_check() {
    let _planted = plant(Plant::IgnoreRateBound);
    assert_eq!(
        rate_margin(),
        Err("a portable deadline outlives the live deadline through the rate bound")
    );
}

#[test]
fn a_recovery_samples_before_it_reads_the_provider() {
    let storage = storage(TEST_CLOCK);
    let buffers = arena_with(4, 5);
    let (mut dev, script) = scripted(&storage, &buffers);
    script.trusted(TEST_EARLIEST, TEST_EARLIEST);
    let counter = storage.platform.sample_counter();
    script.observe(move || counter.load(Ordering::SeqCst));
    storage.platform.ticks(&[Some(NOW), Some(NOW + SECOND)]);
    let before = storage.platform.sample_counter().load(Ordering::SeqCst);
    let (sampled, reading) = dev.volume.recovery_sample();
    assert_eq!(script.observed(), [before + 1]);
    assert_eq!(sampled, Some(NOW));
    let report = dev.volume.report().clock;
    assert_eq!(
        (report.trust, report.last_trusted_at),
        (Some(reading.trust), Some(NOW + SECOND))
    );
}

/// Checks that each publication reads the provider before it takes the portable sample: the reading observes the sample count from before the publication.
fn sampling_order() -> Result<(), &'static str> {
    let storage = storage(TEST_CLOCK);
    let buffers = arena_with(4, 5);
    let (mut dev, script) = scripted(&storage, &buffers);
    script.trusted(TEST_EARLIEST, TEST_EARLIEST);
    let counter = storage.platform.sample_counter();
    script.observe(move || counter.load(Ordering::SeqCst));
    let fill = filled(&storage, &mut dev, &key(1), &[1; 20]);
    let before = storage.platform.sample_counter().load(Ordering::SeqCst);
    drop(
        fill.publish(&mut dev.volume, LIVE, TRIES, &mut budget())
            .unwrap(),
    );
    if script.observed() != [before] {
        return Err("the monotonic sample preceded the reading");
    }
    Ok(())
}

#[test]
fn a_publication_reads_the_provider_before_its_sample() {
    assert_eq!(sampling_order(), Ok(()));
}

/// Planted `SamplingOrder`: a publication that samples before it reads fails the ordering check by name.
#[test]
fn a_publication_that_samples_before_it_reads_fails_the_ordering_check() {
    let _planted = plant(Plant::SamplingOrder);
    assert_eq!(
        sampling_order(),
        Err("the monotonic sample preceded the reading")
    );
}

/// The contract's 24 bytes, hand-laid: scale 1, unit 1, width 64, guarantee 1, protocol 2, reserved 0, provider 1, provenance 1, rate 0, maximum uncertainty 4,000,000.
const GOLDEN_CONTRACT: [u8; 24] = [
    1, 1, 64, 1, 2, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x09, 0x3D, 0x00, 0, 0, 0, 0,
];

/// The golden contract decodes to its tuple, the encoder reproduces it, and each malformed field refuses by name.
#[test]
fn the_golden_contract_decodes_and_each_malformed_field_refuses() {
    encodes_and_decodes(GOLDEN_CONTRACT);
    for (at, byte, refused) in [
        (0, 9, Malformed::Scale),
        (1, 2, Malformed::Unit),
        (2, 32, Malformed::Width),
        (3, 2, Malformed::Guarantee),
        (4, 1, Malformed::Protocol),
        (5, 1, Malformed::Reserved),
        (6, 0, Malformed::Provider),
        (8, 0, Malformed::Provenance),
    ] {
        let mut bytes = GOLDEN_CONTRACT;
        bytes[at] = byte;
        assert_eq!(ClockContract::decode(&bytes), Err(refused), "byte {at}");
    }
}

fn encodes_and_decodes(golden: [u8; 24]) {
    assert_eq!(
        TEST_CLOCK.encode(),
        golden,
        "the encoder reproduces the golden contract byte for byte"
    );
    assert_eq!(ClockContract::decode(&golden), Ok(TEST_CLOCK));
}

/// Zeroing byte 3 models an encoder that leaves byte 3, the guarantee code, at zero.
#[test]
#[should_panic(expected = "the encoder reproduces the golden contract byte for byte")]
fn negative_control_a_golden_without_the_guarantee_code_fails_the_encoder_check() {
    let mut dropped = GOLDEN_CONTRACT;
    dropped[3] = 0;
    encodes_and_decodes(dropped);
}

/// A provider on another scale than the contract's refuses at attach, before the claim.
#[test]
fn attach_refuses_a_provider_of_another_scale() {
    let storage = storage(TEST_CLOCK);
    let buffers = arena_with(4, 5);
    let (disk, _control) = device_with(7, super::super::volume_fixture::BUFFER);
    let (clock, _) = ScriptedClock::on(ClockScale::UtcStepped);
    let refused = Volume::attach(
        &storage,
        &buffers,
        disk,
        clock,
        crate::storage::ServingAuthority::fixture(),
        DEPTH,
        TICK,
        &mut EngineBudget::new(1 << 24),
    )
    .map(|_| ())
    .unwrap_err()
    .0;
    assert_eq!(
        refused,
        AttachError::ClockScale {
            provider: ClockScale::UtcStepped,
            contract: ClockScale::UtcSmeared,
        }
    );
    // The refusal claimed nothing, so an attach with a provider of the contract's scale succeeds.
    let (disk, _control) = device_with(7, super::super::volume_fixture::BUFFER);
    assert!(
        Volume::attach(
            &storage,
            &buffers,
            disk,
            ScriptedClock::trusted(),
            crate::storage::ServingAuthority::fixture(),
            DEPTH,
            TICK,
            &mut EngineBudget::new(1 << 24)
        )
        .is_ok()
    );
}

/// A provider of 4,096 bytes more state raises attach's charge by exactly that much.
#[test]
fn attach_charges_the_boxed_providers_size() {
    struct Large([u8; 4096]);
    impl crate::storage::portable::clock_seal::Sealed for Large {}
    impl PhysicalClock for Large {
        fn scale(&self) -> ClockScale {
            ClockScale::UtcSmeared
        }
        fn read(&mut self) -> Reading {
            Reading::untrusted(if self.0[0] == 0 {
                Untrusted::NoSnapshot
            } else {
                Untrusted::Unknown
            })
        }
    }
    let storage = storage(TEST_CLOCK);
    let buffers = arena_with(4, 5);
    let (disk, _control) = device_with(7, super::super::volume_fixture::BUFFER);
    let small = ScriptedClock::untrusted();
    let large: Box<dyn PhysicalClock> = Box::new(Large([0; 4096]));
    let charge = |clock: &dyn PhysicalClock| {
        Volume::attach_charge(
            &storage,
            &buffers,
            &disk,
            clock,
            &crate::storage::ServingAuthority::fixture(),
            DEPTH,
            TICK,
        )
        .unwrap()
    };
    assert_eq!(
        charge(&*large) - charge(&*small),
        4096 - size_of_val(&*small)
    );
}
