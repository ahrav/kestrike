use super::*;
use crate::failover::report::RecordedRole;
use crate::failover::report::tests as report_tests;
use crate::failover::report::{BuildIdentity, Headroom, WriterId};
use crate::failover::sim::host;
use crate::storage::store_tests::record;

/// An accepted report of `writer` whose attachment and recovery gauges are `attachments` and `recovery`, with every
/// other gauge unavailable.
pub(crate) fn report_of(writer: Host, attachments: Gauge, recovery: Gauge) -> HostReport {
    HostReport {
        writer: WriterId {
            host: writer,
            boot: [0x4b; 16],
        },
        sequence: 1,
        sealed_at_us: 1,
        host: report_tests::unobserved(
            BuildIdentity {
                era: crate::failover::records::ERA,
                digest: None,
            },
            Headroom {
                attachments,
                recovery,
                ..report_tests::unavailable_headroom()
            },
        ),
        entries: Vec::new(),
    }
}

/// A candidate with one free attachment slot and one free recovery slot.
pub(crate) fn roomy(writer: Host) -> HostReport {
    report_of(writer, Gauge::known(2, 3), Gauge::known(0, 1))
}

/// A candidate with 64 free attachment slots and one free recovery slot.
fn plenty(writer: Host) -> HostReport {
    report_of(writer, Gauge::known(0, 64), Gauge::known(0, 1))
}

/// The census of `zone` listing `entry` for `shard` alone, as a reconciler that reserved it wrote it.
pub(crate) fn listing(zone: Zone, shard: Shard, entry: Entry) -> Census {
    Census::empty(zone).spliced(0, 0, Some(row(shard, entry)))
}

/// `census` with `shard`'s slot naming `host` and its target, every other row and the entry count unchanged, as a
/// writer that moved the slot over `census`'s version wrote it; `None` when `census` lists no slot for `shard`.
pub(crate) fn rehosted(census: &Census, shard: Shard, host: Host) -> Option<Census> {
    let at = census.at(shard).ok()?;
    let entry = parsed(&census.rows()[at])?;
    Some(census.spliced(at, 1, Some(row(shard, Entry { host, ..entry }))))
}

pub(crate) fn shard_record(shard: u32, owner: u64, standby: Option<u64>) -> ShardRecord {
    ShardRecord {
        shard: Shard::new(shard).unwrap(),
        owner: host(owner),
        attempts: 2,
        standby: standby.map(host),
        ..record()
    }
}

/// No live standby: a record naming no standby, or a lost one, needs a standby while its owner lives and a fresh
/// host when the owner is lost too; a successor owner that took over and was lost, leaving no standby, needs a fresh
/// host. A live standby and a record at `E = 0` need nothing.
#[test]
fn a_shard_with_no_live_standby_needs_a_designation() {
    let lost = |dead: &'static [u64]| move |h: Host| dead.contains(&h.get());
    for (record, dead, expected) in [
        (shard_record(1, 11, None), &[][..], Some(Need::Standby)),
        (
            shard_record(1, 11, Some(12)),
            &[12][..],
            Some(Need::Standby),
        ),
        (
            shard_record(1, 11, Some(12)),
            &[11, 12][..],
            Some(Need::Fresh),
        ),
        (shard_record(1, 11, None), &[11][..], Some(Need::Fresh)),
        (shard_record(1, 11, Some(12)), &[11][..], None),
        (shard_record(1, 11, Some(12)), &[][..], None),
        (
            ShardRecord {
                attempts: 0,
                ..shard_record(1, 11, None)
            },
            &[11][..],
            None,
        ),
    ] {
        assert_eq!(need(&record, lost(dead)), expected, "{record:?} {dead:?}");
    }
}

/// ENDED-GRANTS-NOTHING in the need: over the volume record of the active volume, an owner or a named standby whose
/// entry is ended or gone counts as lost, so an ended standby asks for a standby and an ended owner beside an ended
/// standby for a fresh host; with both entries live, `need_of` answers as `need`.
#[test]
fn an_ended_owner_or_standby_counts_as_lost() {
    use crate::failover::records::{EventKind, VolumeRecord};
    let record = shard_record(1, 11, Some(12));
    let mut volume = VolumeRecord {
        events: Vec::new(),
        next: 0,
        ..crate::failover::poll_tests::volume(
            crate::failover::records::VolumeState::Active,
            host(11),
        )
    };
    volume.push(EventKind::Attach, host(11), crate::failover::records::ERA);
    volume.push(EventKind::Attach, host(12), crate::failover::records::ERA);
    let none = |_: Host| false;
    assert_eq!(need_of(&record, &volume, none), need(&record, none));
    assert_eq!(need_of(&record, &volume, none), None);
    let mut standby_ended = volume.clone();
    standby_ended.events[1].kind = EventKind::Ended;
    assert_eq!(
        need_of(&record, &standby_ended, none),
        Some(Need::Standby),
        "the named standby's entry ended"
    );
    let mut both_ended = standby_ended.clone();
    both_ended.events[0].kind = EventKind::Ended;
    assert_eq!(need_of(&record, &both_ended, none), Some(Need::Fresh));
    let mut owner_gone = volume.clone();
    owner_gone.events[0].kind = EventKind::Gone;
    assert_eq!(
        need_of(&shard_record(1, 11, None), &owner_gone, none),
        Some(Need::Fresh),
        "the owner's entry is gone and no standby is named"
    );
    assert_eq!(
        need_of(&record, &owner_gone, none),
        None,
        "a live named standby covers an ended owner: its takeover runs"
    );
    let lost =
        |dead: &'static [u64]| move |candidate: Host| dead.iter().any(|&h| host(h) == candidate);
    assert_eq!(
        need_of(&record, &volume, lost(&[12])),
        Some(Need::Standby),
        "the caller's evidence of the live standby's loss"
    );
    assert_eq!(
        need_of(&record, &volume, lost(&[11, 12])),
        Some(Need::Fresh),
        "the caller's evidence of both losses over live entries"
    );
    assert_eq!(
        need_of(&record, &standby_ended, lost(&[11])),
        Some(Need::Fresh),
        "the owner lost by the caller's evidence and the standby by its ended entry"
    );
    let mut standby_detached = volume.clone();
    standby_detached.push(EventKind::Detach, host(12), crate::failover::records::ERA);
    assert_eq!(
        need_of(&record, &standby_detached, none),
        Some(Need::Standby),
        "a named standby whose latest event is a detach holds no live attach"
    );
    let other = VolumeRecord {
        volume: crate::failover::records::VolumeId::new("vol-0c").unwrap(),
        ..both_ended
    };
    for dead in [&[][..], &[12][..]] {
        assert_eq!(
            need_of(&record, &other, lost(dead)),
            need(&record, lost(dead)),
            "another volume's record widens nothing: {dead:?}"
        );
    }
}

fn shard(n: u32) -> Shard {
    Shard::new(n).unwrap()
}

/// The census of zone 1 after admitting host 30 for each of `records` in order under `cap`.
fn census_of(cap: usize, records: &[ShardRecord]) -> Census {
    let mut census = Census::empty(Zone(1));
    for record in records {
        census = Population { cap }
            .admit(
                &census,
                record,
                &plenty(host(30)),
                Attach::Open,
                |_| None,
                |_| false,
            )
            .unwrap()
            .unwrap();
    }
    census
}

fn entry(record: &ShardRecord, h: u64) -> Option<Entry> {
    Some(Entry {
        target: Target::of(record),
        host: host(h),
    })
}

/// No enrollment slot: with `cap` shards listed, a shard the census does not list refuses `Full`, while a listed
/// shard keeps its place, taking no write for its listed host at its listed target and its record's new target
/// after a bump, and a census below the cap admits the shard. A candidate whose attachment or recovery gauge is
/// unavailable or at its limit refuses `Headroom` for a new attach, and so does one whose free attachment slots the
/// census entries of other shards naming it already take, unless its report lists that shard in the standby role; a
/// listed spare of that shard leaves the entry charged. A candidate attached to the active volume takes its slot with
/// a full attachment gauge, listed or not. The owner, a record at `E = 0` and a closed volume refuse before any census
/// change.
/// Entries stay in ascending shard order whatever the order of admission.
#[test]
fn the_population_cap_admits_listed_shards_and_refuses_a_new_one_at_the_cap() {
    let (first, second, third) = (
        shard_record(1, 11, None),
        shard_record(2, 12, None),
        shard_record(3, 13, None),
    );
    let census = census_of(2, &[second, first]);
    let candidate = plenty(host(30));
    let full = Population { cap: 2 };
    let (live, open) = (|_: Host| false, Attach::Open);
    assert_eq!(
        full.admit(&census, &third, &candidate, open, |_| None, live),
        Err(Refusal::Full)
    );
    assert_eq!(
        full.admit(&census, &first, &candidate, open, |_| None, live),
        Ok(None)
    );
    let attached = report_of(host(30), Gauge::known(3, 3), Gauge::known(0, 1));
    assert_eq!(
        full.admit(&census, &first, &attached, Attach::Live, |_| None, live),
        Ok(None)
    );
    let bumped = ShardRecord {
        attempts: first.attempts + 1,
        ..first
    };
    for (report, attach) in [(&candidate, open), (&attached, Attach::Live)] {
        let moved = full
            .admit(&census, &bumped, report, attach, |_| None, live)
            .unwrap()
            .unwrap();
        assert_eq!(
            (moved.len(), moved.slot(shard(1)), moved.slot(shard(2))),
            (2, entry(&bumped, 30), entry(&second, 30))
        );
    }
    assert_eq!(
        full.admit(&census, &bumped, &attached, open, |_| None, live),
        Err(Refusal::Headroom)
    );
    let wide = Population { cap: 3 };
    let grown = wide
        .admit(&census, &third, &candidate, open, |_| None, live)
        .unwrap()
        .unwrap();
    assert_eq!((grown.len(), grown.slot(shard(3))), (3, entry(&third, 30)));
    assert_eq!(grown, Census::decode(&grown.encode()).unwrap());
    assert_eq!(
        Population { cap: 0 }.admit(
            &Census::empty(Zone(1)),
            &third,
            &candidate,
            open,
            |_| None,
            live
        ),
        Err(Refusal::Full)
    );
    for (attachments, recovery) in [
        (Gauge::Unavailable, Gauge::known(0, 1)),
        (Gauge::known(3, 3), Gauge::known(0, 1)),
        (Gauge::known(1, 3), Gauge::known(0, 1)),
        (Gauge::known(0, 3), Gauge::Unavailable),
        (Gauge::known(0, 3), Gauge::known(1, 1)),
    ] {
        assert_eq!(
            wide.admit(
                &census,
                &third,
                &report_of(host(30), attachments, recovery),
                open,
                |_| None,
                live
            ),
            Err(Refusal::Headroom),
            "{attachments:?} {recovery:?}"
        );
    }
    let two_free = report_of(host(30), Gauge::known(0, 3), Gauge::known(0, 1));
    assert!(
        wide.admit(&census, &third, &two_free, open, |_| None, live)
            .is_ok()
    );
    let listing = |role| {
        let mut report = report_of(host(30), Gauge::known(1, 3), Gauge::known(0, 1));
        report.entries = vec![crate::failover::report::VolumeEntry {
            shard: shard(2),
            ..crate::failover::report::tests::bare(second.active.as_str(), role)
        }];
        report
    };
    let known = |held| (held == shard(2)).then(|| ActiveVolume::of(&second));
    let admitted = wide
        .admit(
            &census,
            &third,
            &listing(RecordedRole::Standby),
            open,
            known,
            live,
        )
        .unwrap()
        .unwrap();
    assert_eq!(admitted.slot(shard(3)), entry(&third, 30));
    let moved = ShardRecord {
        active: crate::failover::records::VolumeId::new("vol-0f").unwrap(),
        ..second
    };
    let replaced = |held| (held == shard(2)).then(|| ActiveVolume::of(&moved));
    let earlier = ShardRecord {
        generation: ShardGeneration::new(second.generation.get() - 1).unwrap(),
        ..second
    };
    let behind = |held| (held == shard(2)).then(|| ActiveVolume::of(&earlier));
    let standby = listing(RecordedRole::Standby);
    assert_eq!(
        wide.admit(&census, &third, &standby, open, |_| None, live),
        Err(Refusal::Headroom),
        "a standby listing of a shard whose record the caller lacks leaves the entry charged"
    );
    assert_eq!(
        wide.admit(&census, &third, &standby, open, replaced, live),
        Err(Refusal::Headroom),
        "a standby listing of the shard's old volume leaves the entry charged"
    );
    assert_eq!(
        wide.admit(&census, &third, &standby, open, behind, live),
        Err(Refusal::Headroom),
        "a record below the entry's generation leaves the entry charged"
    );
    assert_eq!(
        wide.admit(
            &census,
            &third,
            &listing(RecordedRole::Replacement),
            open,
            known,
            live
        ),
        Err(Refusal::Headroom),
        "a listed spare of the shard leaves the reserved attach of its active volume pending"
    );
    let unlisted_attached = report_of(host(31), Gauge::known(3, 3), Gauge::known(0, 1));
    assert!(
        Population { cap: 1 }
            .admit(
                &Census::empty(Zone(1)),
                &third,
                &unlisted_attached,
                Attach::Live,
                |_| None,
                live
            )
            .is_ok(),
        "an attached host the census does not list takes the slot with a full attachment gauge"
    );
    let unborn = ShardRecord {
        attempts: 0,
        ..third
    };
    for (record, report, attach, refusal) in [
        (&third, &plenty(host(13)), Attach::Live, Refusal::Ineligible),
        (&unborn, &candidate, open, Refusal::Ineligible),
        (&third, &candidate, Attach::Closed, Refusal::Closed),
    ] {
        assert_eq!(
            wide.admit(&census, record, report, attach, |_| None, live),
            Err(refusal),
            "{record:?} {attach:?}"
        );
    }
}

/// A reservation for the candidate in census row 65 counts against the candidate's attachment headroom.
#[test]
fn a_reservation_in_the_second_census_chunk_counts_against_the_candidate() {
    let census_naming = |last: u64| {
        let mut census = Census::empty(Zone(1));
        for at in 0..65 {
            let record = shard_record(at + 1, 11, None);
            let reserved = if at == 64 { last } else { 31 };
            let row = row(record.shard, entry(&record, reserved).unwrap());
            census = census.spliced(at as usize, 0, Some(row));
        }
        census
    };
    let new = shard_record(66, 11, None);
    let population = Population { cap: 100 };
    let candidate = roomy(host(30));
    let charged = census_naming(30);
    assert_eq!(charged.len(), 65);
    assert_eq!(charged, Census::decode(&charged.encode()).unwrap());
    assert_eq!(
        population.admit(
            &charged,
            &new,
            &candidate,
            Attach::Open,
            |_| None,
            |_| false
        ),
        Err(Refusal::Headroom),
        "one free attachment slot, taken by the row-65 reservation"
    );
    let admitted = population
        .admit(
            &census_naming(32),
            &new,
            &candidate,
            Attach::Open,
            |_| None,
            |_| false,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        admitted.slot(shard(66)),
        entry(&new, 30),
        "row 65 naming another host leaves the slot free"
    );
}

/// Updating a listed shard or inserting one below, between or above the listed shards preserves every other entry's
/// generation, owner, `E` and host.
#[test]
fn an_admission_leaves_every_other_entry_as_it_was() {
    let listed: [(ShardRecord, u64); 3] = core::array::from_fn(|at| {
        let at = at as u32;
        let record = ShardRecord {
            generation: ShardGeneration::new(5 + u64::from(at)).unwrap(),
            attempts: 2 + at,
            ..shard_record(2 * at + 2, 11 + u64::from(at), None)
        };
        (record, 30 + u64::from(at))
    });
    let mut census = Census::empty(Zone(1));
    for (at, (record, reserved)) in listed.iter().enumerate() {
        let row = row(record.shard, entry(record, *reserved).unwrap());
        census = census.spliced(at, 0, Some(row));
    }
    assert_eq!(census, Census::decode(&census.encode()).unwrap());
    let population = Population { cap: 8 };
    for changed in 1..=7 {
        let record = ShardRecord {
            generation: ShardGeneration::new(9).unwrap(),
            attempts: 9,
            ..shard_record(changed, 20, None)
        };
        let admitted = population
            .admit(
                &census,
                &record,
                &plenty(host(40)),
                Attach::Open,
                |_| None,
                |_| true,
            )
            .unwrap()
            .unwrap();
        assert_eq!(admitted, Census::decode(&admitted.encode()).unwrap());
        assert_eq!(admitted.len(), 3 + usize::from(changed % 2 == 1));
        assert_eq!(admitted.slot(record.shard), entry(&record, 40));
        for (other, reserved) in &listed {
            if other.shard != record.shard {
                assert_eq!(
                    admitted.slot(other.shard),
                    entry(other, *reserved),
                    "admitting shard {changed}"
                );
            }
        }
    }
}

/// ONE-HOST-PER-SLOT: a slot listed for one host refuses another candidate `Taken` while the incumbent is live, at
/// the record's target or an earlier one, and so does a record naming a live standby; evidence that the incumbent is
/// lost moves the slot to the candidate in place. Another candidate with a full attachment gauge refuses `Headroom`
/// on the listed slot before the incumbent check, whether the incumbent is lost or live. The listed host itself
/// retakes its slot at a later target with a full gauge while it holds a live attach of the active volume, and at
/// the next generation, after a flip to a volume it is not attached to, the same full gauge refuses `Headroom`; an
/// entry whose host the record now names owner names no incumbent.
#[test]
fn a_slot_moves_to_another_host_only_when_its_incumbent_is_lost() {
    let first = shard_record(1, 11, None);
    let census = census_of(1, &[first]);
    let other = roomy(host(31));
    let cap = Population { cap: 1 };
    let open = Attach::Open;
    assert_eq!(
        cap.admit(&census, &first, &other, open, |_| None, |_| false),
        Err(Refusal::Taken)
    );
    let moved = cap
        .admit(&census, &first, &other, open, |_| None, |h| h == host(30))
        .unwrap()
        .unwrap();
    assert_eq!((moved.len(), moved.slot(shard(1))), (1, entry(&first, 31)));
    let starved = report_of(host(31), Gauge::known(3, 3), Gauge::known(0, 1));
    for gone in [false, true] {
        assert_eq!(
            cap.admit(
                &census,
                &first,
                &starved,
                open,
                |_| None,
                |h| gone && h == host(30)
            ),
            Err(Refusal::Headroom),
            "incumbent lost: {gone}"
        );
    }
    let named = ShardRecord {
        standby: Some(host(30)),
        ..first
    };
    let empty = Census::empty(Zone(1));
    assert_eq!(
        cap.admit(&empty, &named, &other, open, |_| None, |_| false),
        Err(Refusal::Taken)
    );
    assert!(
        cap.admit(&empty, &named, &other, open, |_| None, |h| h == host(30))
            .is_ok()
    );
    let bumped = ShardRecord {
        attempts: first.attempts + 1,
        ..first
    };
    assert_eq!(
        cap.admit(&census, &bumped, &other, open, |_| None, |_| false),
        Err(Refusal::Taken)
    );
    let attached = report_of(host(30), Gauge::known(3, 3), Gauge::known(0, 1));
    let retaken = cap
        .admit(
            &census,
            &bumped,
            &attached,
            Attach::Live,
            |_| None,
            |_| false,
        )
        .unwrap()
        .unwrap();
    assert_eq!(retaken.slot(shard(1)), entry(&bumped, 30));
    let flipped = ShardRecord {
        generation: ShardGeneration::new(first.generation.get() + 1).unwrap(),
        owner: host(32),
        attempts: 1,
        ..first
    };
    assert_eq!(
        cap.admit(&census, &flipped, &attached, open, |_| None, |_| false),
        Err(Refusal::Headroom)
    );
    let reattached = cap
        .admit(
            &census,
            &flipped,
            &roomy(host(30)),
            open,
            |_| None,
            |_| false,
        )
        .unwrap()
        .unwrap();
    assert_eq!(reattached.slot(shard(1)), entry(&flipped, 30));
    let taken_over = ShardRecord {
        owner: host(30),
        attempts: first.attempts + 1,
        ..first
    };
    let rebound = cap
        .admit(&census, &taken_over, &other, open, |_| None, |_| false)
        .unwrap()
        .unwrap();
    assert_eq!(rebound.slot(shard(1)), entry(&taken_over, 31));
}

/// CENSUS-COVERS: an entry leaves only for a record that names no standby at another `(g, owner, E)` than the
/// entry's, while the entry's host is the record's owner or holds no live attach of the active volume; a record
/// still at the entry's target, where a reserved designation can commit, a record naming a standby at any target, an
/// attached host that is not the owner, and a shard the census does not list keep the census as it is.
#[test]
fn a_census_entry_leaves_only_after_its_tenure_moved_with_no_standby() {
    let reserved = shard_record(1, 11, None);
    let census = census_of(2, &[reserved, shard_record(2, 12, None)]);
    let taken = ShardRecord {
        owner: host(21),
        attempts: reserved.attempts + 1,
        ..reserved
    };
    let (detached, attached) = (|_: Host| false, |h: Host| h == host(30));
    let released = census.released(&taken, detached).unwrap();
    assert_eq!((released.len(), released.slot(shard(1))), (1, None));
    assert!(released.slot(shard(2)).is_some());
    assert_eq!(census.released(&taken, attached), None);
    let promoted = ShardRecord {
        owner: host(30),
        ..taken
    };
    assert_eq!(census.released(&promoted, attached), Some(released));
    let named = |record: ShardRecord| ShardRecord {
        standby: Some(host(21)),
        ..record
    };
    let bumped = ShardRecord {
        attempts: reserved.attempts + 1,
        ..reserved
    };
    for kept in [
        reserved,
        named(reserved),
        named(bumped),
        shard_record(3, 13, None),
    ] {
        assert_eq!(census.released(&kept, detached), None, "{kept:?}");
    }
}

/// The census codec: an encoding is 10 bytes and 28 per entry and decodes to its value; a truncated or extended
/// value, another magic or version, a count that disagrees with the length, shards out of ascending order or
/// repeated, a zero shard, generation, owner or host and `E` above `ATTEMPTS_MAX` refuse. A successor keeps its
/// zone. A census of `MAX_SLOTS` entries encodes to `CENSUS_MAX` bytes and decodes, a count above `MAX_SLOTS` refuses,
/// and a full census admits no further shard under any cap.
#[test]
fn the_census_codec_accepts_exactly_its_encodings() {
    let census = census_of(2, &[shard_record(1, 11, None), shard_record(2, 12, None)]);
    let bytes = census.encode();
    assert_eq!(bytes.len(), 10 + 2 * 28);
    assert_eq!(&bytes[..10], [b'S', b'T', b'B', b'Y', 0, 1, 0, 1, 0, 2]);
    assert_eq!(Census::decode(&bytes), Ok(census.clone()));
    assert_eq!(
        Census::decode(&Census::empty(Zone(7)).encode()),
        Ok(Census::empty(Zone(7)))
    );
    let patched = |at: usize, with: &[u8]| {
        let mut bytes = bytes.clone();
        bytes[at..at + with.len()].copy_from_slice(with);
        Census::decode(&bytes)
    };
    assert_eq!(
        Census::decode(&bytes[..bytes.len() - 1]),
        Err(CodecError::Length)
    );
    assert_eq!(
        Census::decode(&[&bytes[..], &[0]].concat()),
        Err(CodecError::Length)
    );
    assert_eq!(patched(0, b"STBX"), Err(CodecError::Magic));
    assert_eq!(patched(4, &[0, 2]), Err(CodecError::Version));
    assert_eq!(patched(8, &[0, 1]), Err(CodecError::Length));
    for (name, at, with) in [
        ("zero shard", 10, &[0u8; 4][..]),
        ("descending shards", 10, &[0, 0, 0, 3][..]),
        ("repeated shard", 38, &[0, 0, 0, 1][..]),
        ("zero generation", 14, &[0; 4][..]),
        ("zero owner", 18, &[0; 8][..]),
        ("E above the maximum", 26, &[0xFF; 4][..]),
        ("zero host", 30, &[0; 8][..]),
    ] {
        assert_eq!(patched(at, with), Err(CodecError::Field), "{name}");
    }
    assert_eq!(census.succeeds(&census), Ok(()));
    assert_eq!(
        Census::empty(Zone(2)).succeeds(&census),
        Err(SuccessorRule::Identity)
    );
    let mut encoded = Census::empty(Zone(1)).encode();
    encoded[8..10].copy_from_slice(&(MAX_SLOTS as u16).to_be_bytes());
    for n in 1..=MAX_SLOTS as u32 {
        encoded.extend(row(
            shard(n),
            entry(&shard_record(n, 11, None), 30).unwrap(),
        ));
    }
    assert_eq!(encoded.len(), CENSUS_MAX);
    let largest = Census::decode(&encoded).unwrap();
    assert_eq!(largest.len(), MAX_SLOTS);
    assert_eq!(largest.encode(), encoded);
    let mut over = encoded;
    over[8..10].copy_from_slice(&(MAX_SLOTS as u16 + 1).to_be_bytes());
    over.extend([0; CENSUS_ENTRY]);
    assert_eq!(Census::decode(&over), Err(CodecError::Length));
    let next = shard_record(MAX_SLOTS as u32 + 1, 11, None);
    assert_eq!(
        Population { cap: usize::MAX }.admit(
            &largest,
            &next,
            &plenty(host(31)),
            Attach::Open,
            |_| None,
            |_| false
        ),
        Err(Refusal::Full),
        "a census at MAX_SLOTS admits no shard whatever the cap"
    );
}

fn write_check(census: &Census) -> Result<(), CodecError> {
    census.clone().lend().map(drop)
}

#[test]
fn a_census_passes_the_write_check_exactly_when_its_encoding_decodes() {
    let first = shard_record(1, 11, None);
    let census = census_of(2, &[first, shard_record(2, 12, None)]);
    assert_eq!(write_check(&census), Ok(()));
    assert_eq!(
        write_check(&Census::decode(&census.encode()).unwrap()),
        Ok(())
    );
    let reserved = entry(&first, 30).unwrap();
    let refused = [
        (
            "the owner as host",
            Entry {
                host: first.owner,
                ..reserved
            },
        ),
        (
            "E = 0",
            Entry {
                target: Target {
                    attempts: 0,
                    ..reserved.target
                },
                ..reserved
            },
        ),
        (
            "E above the maximum",
            Entry {
                target: Target {
                    attempts: ATTEMPTS_MAX + 1,
                    ..reserved.target
                },
                ..reserved
            },
        ),
    ];
    for (name, held) in refused {
        let listed = listing(Zone(1), shard(1), held);
        assert_eq!(write_check(&listed), Err(CodecError::Field), "{name}");
        assert_eq!(
            Census::decode(&listed.encode()),
            Err(CodecError::Field),
            "{name}"
        );
        let repaired = Population { cap: 1 }
            .admit(
                &listed,
                &first,
                &plenty(host(31)),
                Attach::Open,
                |_| None,
                |_| true,
            )
            .unwrap()
            .unwrap();
        assert_eq!(write_check(&repaired), Ok(()), "{name}");
        assert_eq!(
            Census::decode(&repaired.encode()).as_ref(),
            Ok(&repaired),
            "{name}"
        );
    }
    let over = ShardRecord {
        attempts: ATTEMPTS_MAX + 1,
        ..shard_record(3, 13, None)
    };
    let grown = Population { cap: 3 }
        .admit(
            &census,
            &over,
            &plenty(host(30)),
            Attach::Open,
            |_| None,
            |_| false,
        )
        .unwrap()
        .unwrap();
    assert_eq!(write_check(&grown), Err(CodecError::Field));
    let moved = ShardRecord {
        attempts: 5,
        ..shard_record(3, 13, None)
    };
    let dropped = grown.released(&moved, |_| false).unwrap();
    assert_eq!(write_check(&dropped), Ok(()));
    assert_eq!(dropped, census);
    let disordered =
        listing(Zone(1), shard(2), reserved).spliced(1, 0, Some(row(shard(1), reserved)));
    assert_eq!(write_check(&disordered), Err(CodecError::Field));
    assert_eq!(Census::decode(&disordered.encode()), Err(CodecError::Field));
}

fn encoding_of(shards: &[u32]) -> Vec<u8> {
    let mut bytes = Census::empty(Zone(1)).encode();
    bytes[8..10].copy_from_slice(&(shards.len() as u16).to_be_bytes());
    for &n in shards {
        bytes.extend(row(
            shard(n),
            entry(&shard_record(n, 11, None), 30).unwrap(),
        ));
    }
    bytes
}

#[test]
fn a_decode_beside_a_kept_census_equals_a_decode_alone() {
    let shards: Vec<u32> = (1..=200).map(|n| 3 * n).collect();
    let kept = Some(Census::decode(&encoding_of(&shards)).unwrap());
    let field = |at: usize, offset: usize| 10 + 28 * at + offset;
    let mut cases = vec![encoding_of(&shards)];
    for at in [0, 1, 63, 64, 65, 127, 128, 191, 192, 199] {
        let mut moved = shards.clone();
        moved[at] += 1;
        cases.push(encoding_of(&moved));
        let mut grown = shards.clone();
        grown.insert(at, shards[at] - 1);
        cases.push(encoding_of(&grown));
        let mut shrunk = shards.clone();
        shrunk.remove(at);
        cases.push(encoding_of(&shrunk));
        let mut zero_host = encoding_of(&shards);
        zero_host[field(at, 20)..field(at, 28)].fill(0);
        cases.push(zero_host);
        let mut owner_host = encoding_of(&shards);
        owner_host.copy_within(field(at, 8)..field(at, 16), field(at, 20));
        cases.push(owner_host);
        let mut repeated = encoding_of(&shards);
        if at > 0 {
            repeated.copy_within(field(at - 1, 0)..field(at - 1, 4), field(at, 0));
        } else {
            repeated[field(0, 0)..field(0, 4)].fill(0);
        }
        cases.push(repeated);
    }
    cases.push(encoding_of(&[]));
    cases.push(encoding_of(&shards[..64]));
    cases.push(encoding_of(&shards[..63]));
    let mut truncated = encoding_of(&shards);
    truncated.pop();
    cases.push(truncated);
    let refused = Some(listing(
        Zone(1),
        shard(3),
        Entry {
            host: host(11),
            ..entry(&shard_record(3, 11, None), 30).unwrap()
        },
    ));
    let mut accepted = 0;
    for (at, bytes) in cases.iter().enumerate() {
        let alone = Census::decode_owned(bytes.clone());
        accepted += usize::from(alone.is_ok());
        for memo in [&kept, &refused, &None] {
            assert_eq!(Census::decode_like(bytes.clone(), memo), alone, "case {at}");
        }
    }
    assert!(accepted > 20 && accepted < cases.len() - 20);
    assert_eq!(
        Census::decode_like(refused.as_ref().unwrap().encode(), &refused),
        Err(CodecError::Field),
        "bytes equal to a kept census the decoder refuses"
    );
}

/// A census one byte longer than its count gives, under the magic `STBX`, refuses `Length`: `Record::decode`
/// returns the first failing check in the order length, magic, version. Each fault alone refuses with its own kind,
/// `Length` and `Magic`, so the refusal of both names the check that ran first.
#[test]
fn a_census_of_the_wrong_length_and_magic_refuses_for_its_length() {
    let sound = Census::empty(Zone(7)).encode();
    assert_eq!(Census::decode(&sound), Ok(Census::empty(Zone(7))));

    let mut long = sound.clone();
    long.push(0);
    assert_eq!(Census::decode(&long), Err(CodecError::Length));
    let mut renamed = sound.clone();
    renamed[..4].copy_from_slice(b"STBX");
    assert_eq!(Census::decode(&renamed), Err(CodecError::Magic));

    let mut both = long;
    both[..4].copy_from_slice(b"STBX");
    assert_eq!(
        Census::decode(&both),
        Err(CodecError::Length),
        "a census one byte too long under another magic"
    );
}

/// A census one byte longer than its count gives, under format version 2, refuses `Length`: `Record::decode` checks
/// the length before the version.
#[test]
fn a_census_of_the_wrong_length_and_version_refuses_for_its_length() {
    let mut both = Census::empty(Zone(7)).encode();
    both.push(0);
    both[4..6].copy_from_slice(&2u16.to_be_bytes());
    assert_eq!(Census::decode(&both), Err(CodecError::Length));
}

/// Every proper prefix of an empty census under the magic `STBX` refuses `Length`, where the whole of it refuses
/// `Magic`. An empty census is its 10-byte fixed part, which the count ends, so each prefix is shorter than any
/// count's length, and `Record::decode` checks the length before the magic.
#[test]
fn a_prefix_of_an_empty_census_under_another_magic_refuses_for_its_length() {
    let mut renamed = Census::empty(Zone(7)).encode();
    renamed[..4].copy_from_slice(b"STBX");
    assert_eq!(renamed.len(), 10);
    assert_eq!(Census::decode(&renamed), Err(CodecError::Magic));
    for len in 0..renamed.len() {
        assert_eq!(
            Census::decode(&renamed[..len]),
            Err(CodecError::Length),
            "the first {len} bytes"
        );
    }
}
