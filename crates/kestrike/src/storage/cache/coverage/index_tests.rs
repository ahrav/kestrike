//! Indexed page writes produce the same page values and acknowledgments as writes that scan the whole page. When
//! the index lookup returns `Err(Unindexed)`, the write scans the whole page.

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::panic::{AssertUnwindSafe, catch_unwind};

use super::super::super::seeded::SplitMix64;
use super::super::super::store::sim::{Arm, MemLog, Shared};
use super::super::super::store::{Client, ITEM_LIMIT, Key, Read};
use super::super::super::store_tests::{page, record, seeded, shard};
use super::tests::{interval, key_among};
use super::{
    Cover, Entry, Fencing, INDEX_PLANT, IndexPlant, Interval, KeyHash, KeyIndex, LOOKUPS, Limits,
    Next, Op, PageReply, PageRequest, Progress, Unindexed, Withdraw, decode_entries,
    encode_entries, home_slot, merged, page_len, page_of,
};
use crate::failover::records::{CoveragePage, ShardRecord};
use crate::storage::session_at;

const SEEDS: [u64; 5] = [
    0x243F_6A88_85A3_08D3,
    0x1319_8A2E_0370_7344,
    0xA409_3822_299F_31D0,
    0x082E_FA98_EC4E_6C89,
    0x4528_21E6_38D0_1377,
];

struct Planted;

impl Planted {
    fn new(plant: IndexPlant) -> Self {
        INDEX_PLANT.with(|cell| cell.set(plant));
        LOOKUPS.with(|lookups| *lookups.borrow_mut() = Some(Vec::new()));
        Self
    }

    fn lookups(&self) -> Vec<Result<(), Unindexed>> {
        LOOKUPS.with(|lookups| lookups.borrow().clone().unwrap_or_default())
    }
}

impl Drop for Planted {
    fn drop(&mut self) {
        INDEX_PLANT.with(|cell| cell.set(IndexPlant::Used));
        LOOKUPS.with(|lookups| *lookups.borrow_mut() = None);
    }
}

fn mark(key: &[u8; 32]) -> u32 {
    KeyHash::of(&SEEDS, key).mark()
}

fn fenced(client: &mut Client<Shared, MemLog>, record: &ShardRecord, intervals: usize) -> Fencing {
    let mut fencing = Fencing::new(record, &session_at(3, 0), intervals).unwrap();
    fencing.coverage.seeds = SEEDS;
    for _ in 0..4 {
        if fencing.fence_all(client) == Ok(Progress::Done) {
            return fencing;
        }
    }
    panic!("the fence did not complete");
}

#[derive(Debug, Clone)]
enum Step {
    Write(Vec<Entry>),
    Raced(Vec<Entry>, Vec<Entry>),
    Foreign(Entry),
    Arm(Arm),
    RereadUnavailable,
    Limit(usize),
}

#[derive(Debug, Clone)]
struct History {
    intervals: usize,
    page_cap: u32,
    steps: Vec<Step>,
}

type Trace = Vec<String>;

fn history(case: u64) -> History {
    let mut rng = SplitMix64::new(0x1821_1000 ^ case);
    let pages = record().pages;
    let pool: Vec<Vec<[u8; 32]>> = (0..pages.get())
        .map(|page| {
            let mut keys: Vec<[u8; 32]> =
                (0..7).map(|_| key_among(&mut rng, pages, page)).collect();
            for at in 0..3 {
                let mut twin = keys[at];
                twin[31] ^= 0x80;
                keys.push(twin);
            }
            assert!(keys.iter().all(|key| page_of(key, pages) == page));
            keys
        })
        .collect();
    let mut drawn: Vec<Entry> = Vec::new();
    let mut entries = |rng: &mut SplitMix64, page: u16| -> Vec<Entry> {
        let count = 1 + rng.below(6);
        (0..count)
            .map(|_| {
                let on_page: Vec<Entry> = (drawn.iter())
                    .filter(|(key, _)| page_of(key, pages) == page)
                    .copied()
                    .collect();
                let entry = if !on_page.is_empty() && rng.below(3) == 0 {
                    let (key, was) = on_page[rng.below(on_page.len() as u64) as usize];
                    let low = was.low().0.saturating_sub(rng.below(3));
                    (key, interval(low, was.high().0 + rng.below(3)))
                } else {
                    let keys = &pool[usize::from(page)];
                    let low = rng.below(24);
                    (
                        keys[rng.below(keys.len() as u64) as usize],
                        interval(low, low + rng.below(4)),
                    )
                };
                drawn.push(entry);
                entry
            })
            .collect()
    };
    let mut steps = Vec::new();
    for _ in 0..48 {
        let page = rng.below(u64::from(pages.get())) as u16;
        let step = match rng.below(21) {
            0 => Step::Arm(Arm::Timeout { commit: true }),
            1 => Step::Arm(Arm::Timeout { commit: false }),
            2 => Step::Arm(Arm::Unavailable),
            3 => Step::Limit(match rng.below(3) {
                0 => page_len(6),
                _ => ITEM_LIMIT,
            }),
            4 => Step::Foreign(entries(&mut rng, page)[0]),
            5 | 6 => {
                let other = rng.below(u64::from(pages.get())) as u16;
                Step::Raced(entries(&mut rng, page), entries(&mut rng, other))
            }
            7 => Step::RereadUnavailable,
            _ => Step::Write(entries(&mut rng, page)),
        };
        steps.push(step);
    }
    History {
        intervals: rng.below(4) as usize,
        page_cap: [page_len(12) as u32, 65536][rng.below(2) as usize],
        steps,
    }
}

fn outcome(result: &Result<Cover, Withdraw>) -> String {
    match result {
        Ok(Cover::Done) => "done".to_owned(),
        Ok(Cover::Unresolved) => "unresolved".to_owned(),
        Ok(Cover::Rebased) => "rebased".to_owned(),
        Ok(Cover::Next(_)) => "next".to_owned(),
        Err(withdraw) => format!("{withdraw:?}"),
    }
}

struct Replay {
    store: Shared,
    client: Client<Shared, MemLog>,
    fencing: Fencing,
    trace: Trace,
    armed: Option<Arm>,
    reread_fault: bool,
}

impl Replay {
    fn run(&mut self, request: PageRequest) -> PageReply {
        if let Some(arm) = self.armed.take() {
            self.store.schedule(arm);
        } else if matches!(request.op, Op::Reread { .. }) && self.reread_fault {
            self.reread_fault = false;
            self.store.schedule(Arm::Unavailable);
        }
        request.run(&mut self.client)
    }

    fn finish(&mut self, mut request: PageRequest) {
        loop {
            let reply = self.run(request);
            let result = self.fencing.cover_end(reply);
            self.trace.push(outcome(&result));
            match result {
                Ok(Cover::Next(next)) => request = next,
                _ => return,
            }
        }
    }

    fn begun(&mut self, entries: &[Entry]) -> Option<PageRequest> {
        match self.fencing.cover_begin(entries) {
            Ok(Some(request)) => {
                self.trace.push(format!("{:?}", self.fencing.partial()));
                Some(request)
            }
            Ok(None) => {
                self.trace.push("unfenced".to_owned());
                None
            }
            Err(withdraw) => {
                self.trace.push(format!("{withdraw:?}"));
                None
            }
        }
    }
}

struct Replayed {
    trace: Trace,
    lookups: Vec<Result<(), Unindexed>>,
    saturated: usize,
}

fn replay(history: &History, plant: IndexPlant) -> Replayed {
    let planted = Planted::new(plant);
    let store = seeded();
    let mut client = Client::open(store.clone(), MemLog::default()).unwrap();
    let fenced_record = ShardRecord {
        page_cap: NonZeroU32::new(history.page_cap).unwrap(),
        ..record()
    };
    let fencing = fenced(&mut client, &fenced_record, history.intervals);
    let limits = Limits {
        intervals: history.intervals,
        page_bytes: history.page_cap as usize,
    };
    let mut replay = Replay {
        store: store.clone(),
        client,
        fencing,
        trace: Trace::new(),
        armed: None,
        reread_fault: false,
    };
    let mut saturated = 0;
    for step in &history.steps {
        match step {
            Step::Write(entries) => {
                if let Some(request) = replay.begun(entries) {
                    replay.finish(request);
                }
            }
            Step::Raced(first, second) => {
                let first = replay.begun(first);
                let second = replay.begun(second);
                let first = first.map(|request| replay.run(request));
                if let Some(second) = second {
                    let reply = replay.run(second);
                    if let Some(first) = first {
                        let result = replay.fencing.cover_end(first);
                        replay.trace.push(outcome(&result));
                    }
                    let result = replay.fencing.cover_end(reply);
                    replay.trace.push(outcome(&result));
                    if let Ok(Cover::Next(next)) = result {
                        replay.finish(next);
                    }
                }
            }
            Step::Foreign(entry) => {
                let mut other = Client::open(store.clone(), MemLog::default()).unwrap();
                let at = page_of(&entry.0, record().pages);
                if let Ok(read) = other.read::<CoveragePage>(Key::Page(shard(), at))
                    && let Some(next) = merged(read.value(), *entry, limits)
                {
                    let written = other.replace(&read, next).is_ok();
                    replay.trace.push(format!("foreign {written:?}"));
                }
            }
            Step::Arm(arm) => replay.armed = Some(*arm),
            Step::RereadUnavailable => replay.reread_fault = true,
            Step::Limit(limit) => store.0.borrow_mut().limit = *limit,
        }
        if !matches!(step, Step::Arm(_) | Step::RereadUnavailable) {
            replay.armed = None;
            replay.reread_fault = false;
        }
        for at in 0..record().pages.get() {
            let stored = page(&store, at);
            saturated += usize::from(stored.saturated);
            let known =
                (replay.fencing.known(at)).map(|read| (read.version(), read.value().clone()));
            replay
                .trace
                .push(format!("page {at}: {stored:?} known {known:?}"));
        }
        replay.trace.push(format!("{:?}", replay.fencing.partial()));
    }
    Replayed {
        trace: replay.trace,
        lookups: planted.lookups(),
        saturated,
    }
}

/// For the same `case`, replay under `plant` must match the full page scan's trace.
#[track_caller]
fn assert_index_changes_nothing(case: u64, plant: IndexPlant) -> Replayed {
    let history = history(case);
    let without = replay(&history, IndexPlant::Unused);
    assert!(
        without.lookups.is_empty(),
        "the run without the index consulted one"
    );
    let with = replay(&history, plant);
    assert_eq!(
        with.trace, without.trace,
        "case {case}: the page bytes and acknowledgments with the index equal those without it"
    );
    with
}

#[derive(Debug, Default)]
struct Tally {
    used: usize,
    stale: usize,
    miss: usize,
    mismatch: usize,
    crowded: usize,
    saturated: usize,
}

fn tally(cases: std::ops::Range<u64>, plant: IndexPlant) -> Tally {
    let mut tally = Tally::default();
    for case in cases {
        let replayed = assert_index_changes_nothing(case, plant);
        tally.saturated += replayed.saturated;
        for lookup in replayed.lookups {
            match lookup {
                Ok(()) => tally.used += 1,
                Err(Unindexed::Stale) => tally.stale += 1,
                Err(Unindexed::Miss) => tally.miss += 1,
                Err(Unindexed::Mismatch) => tally.mismatch += 1,
                Err(Unindexed::Crowded) => tally.crowded += 1,
            }
        }
    }
    tally
}

#[test]
fn page_writes_and_acknowledgments_with_the_index_equal_those_without_it() {
    let tally = tally(0..300, IndexPlant::Used);
    assert!(
        tally.used > 2000 && tally.miss > 50 && tally.saturated > 50 && tally.mismatch == 0,
        "{tally:?}"
    );
}

#[test]
fn an_index_off_by_one_chunk_is_caught_by_the_key_check() {
    let tally = tally(0..100, IndexPlant::OffByOne);
    assert!(tally.used == 0 && tally.mismatch > 300, "{tally:?}");
}

#[test]
fn an_index_one_write_stale_is_refused_by_the_value_it_names() {
    let used = tally(0..100, IndexPlant::Used);
    let stale = tally(0..100, IndexPlant::Stale);
    assert!(
        stale.stale > 300 && stale.used * 4 < used.used && stale.mismatch == 0,
        "{stale:?} against {used:?}"
    );
}

#[test]
fn an_index_one_write_stale_under_the_current_version_fails_the_property() {
    let (mut failed, mut caught) = (0, 0);
    for case in 0..100 {
        let checked = catch_unwind(AssertUnwindSafe(|| {
            assert_index_changes_nothing(case, IndexPlant::Restamped)
        }));
        match checked {
            Ok(replayed) => {
                caught += usize::from(replayed.lookups.contains(&Err(Unindexed::Mismatch)));
            }
            Err(payload) => {
                let message =
                    (payload.downcast_ref::<String>()).expect("an assertion's formatted message");
                assert!(
                    message.contains("with the index equal those without it"),
                    "{message}"
                );
                failed += 1;
            }
        }
    }
    assert!(failed > 0 && caught > 0, "{failed} failed, {caught} caught");
}

fn stored(entries: &[Entry]) -> Read<CoveragePage> {
    let store = seeded();
    let mut client = Client::open(store.clone(), MemLog::default()).unwrap();
    let read = client.read::<CoveragePage>(Key::Page(shard(), 0)).unwrap();
    let next = CoveragePage {
        entries: encode_entries(entries),
        ..read.value().clone()
    };
    client.replace(&read, next).unwrap()
}

fn asked(
    index: &KeyIndex,
    read: &Read<CoveragePage>,
    key: [u8; 32],
) -> Result<Vec<(u32, Interval)>, Unindexed> {
    let mut held = vec![Some(Vec::new())];
    let entries = [(key, interval(1, 1))];
    let page = &read.value().entries;
    index.found(page, read.version(), &entries, &[false], &mut held)?;
    Ok(held.pop().flatten().unwrap())
}

fn scanned(read: &Read<CoveragePage>, key: [u8; 32]) -> Vec<(u32, Interval)> {
    (0..)
        .zip(decode_entries(&read.value().entries).unwrap())
        .filter(|(_, (other, _))| *other == key)
        .map(|(position, (_, interval))| (position, interval))
        .collect()
}

#[test]
fn a_key_index_answers_as_a_scan_of_its_value_does() {
    let mut rng = SplitMix64::new(0x1821_2000);
    let mut keys = std::iter::repeat_with(move || {
        let mut key = [0; 32];
        for byte in &mut key {
            *byte = rng.next_u64() as u8;
        }
        key
    });
    let mut last = keys.by_ref().filter(|key| home_slot(mark(key), 16) == 15);
    let (wrap, wrapped) = (last.next().unwrap(), last.next().unwrap());
    let many = keys.next().unwrap();
    let mut seen = HashMap::new();
    let (twin, absent_twin) = keys
        .by_ref()
        .find_map(|key| seen.insert(mark(&key), key).map(|earlier| (earlier, key)))
        .unwrap();
    let absent = keys.find(|key| mark(key) != mark(&twin)).unwrap();
    assert!(twin != absent_twin && mark(&twin) == mark(&absent_twin));
    let value = [
        (many, interval(1, 1)),
        (wrap, interval(1, 2)),
        (many, interval(3, 3)),
        (twin, interval(1, 1)),
        (wrapped, interval(2, 2)),
        (many, interval(5, 5)),
        (keys.next().unwrap(), interval(1, 1)),
        (keys.next().unwrap(), interval(1, 1)),
    ];
    let read = stored(&value);
    let mut index = KeyIndex::new(SEEDS);
    assert_eq!(asked(&index, &read, many), Err(Unindexed::Stale));
    index.build(&read);
    assert_eq!(index.slots.len(), 16);
    let slot_of = |index: &KeyIndex, position: u64| {
        (index.slots.iter()).position(|&slot| slot != 0 && slot & 0xFFFF_FFFF == position)
    };
    assert!(slot_of(&index, 4).unwrap() < 15, "the second probe wrapped");
    for key in [many, wrap, wrapped, twin] {
        assert_eq!(asked(&index, &read, key), Ok(scanned(&read, key)));
    }
    assert_eq!(asked(&index, &read, absent), Err(Unindexed::Miss));
    assert_eq!(asked(&index, &read, absent_twin), Err(Unindexed::Mismatch));

    let mut descending = index.clone();
    let (first, second) = (slot_of(&index, 0).unwrap(), slot_of(&index, 2).unwrap());
    descending.slots.swap(first, second);
    assert_eq!(asked(&descending, &read, many), Err(Unindexed::Mismatch));

    let mut miscounted = index.clone();
    miscounted.of = miscounted.of.map(|(version, count)| (version, count + 1));
    assert_eq!(asked(&miscounted, &read, many), Err(Unindexed::Stale));

    let (chunks, _) = read.value().entries.as_chunks();
    assert_eq!(
        index.chunks(chunks, &many, &mut Vec::new(), &mut 1),
        Err(Unindexed::Crowded)
    );
    assert_eq!(
        index.chunks(chunks, &absent, &mut vec![(0, interval(1, 1))], &mut 99),
        Err(Unindexed::Miss)
    );
}

/// A build that spends its probe budget names no value, so no lookup reads its partial table. The `m` chunks of one
/// key share a home slot, so their build visits `m * (m - 1) / 2` occupied slots against a budget of `8 * m`: 136 of
/// 136 for 17 chunks, which completes, and 153 of 144 for 18, which stops.
#[test]
fn a_build_that_spends_its_probe_budget_names_no_value() {
    let key = [0x5A; 32];
    let chunks = |count: u64| -> Vec<Entry> {
        (1..=count)
            .map(|at| (key, interval(2 * at, 2 * at)))
            .collect()
    };
    let mut index = KeyIndex::new(SEEDS);

    let within = stored(&chunks(17));
    index.build(&within);
    assert_eq!(index.of, Some((within.version(), 17)));
    assert_eq!(asked(&index, &within, key), Ok(scanned(&within, key)));

    let past = stored(&chunks(18));
    index.build(&past);
    assert_eq!(index.of, None);
    assert_eq!(asked(&index, &past, key), Err(Unindexed::Stale));
}

#[test]
fn a_write_whose_index_answers_nothing_takes_its_chunks_from_the_page() {
    let store = seeded();
    let mut client = Client::open(store.clone(), MemLog::default()).unwrap();
    let mut fencing = fenced(&mut client, &record(), 4);
    let mut key = [0x33; 32];
    key[..8].copy_from_slice(&1_u64.to_le_bytes());
    let mut other = key;
    other[31] ^= 1;
    let mut beside = [0x44; 32];
    beside[..8].copy_from_slice(&3_u64.to_le_bytes());
    assert_eq!(page_of(&key, record().pages), 1);
    assert_eq!(page_of(&beside, record().pages), 1);
    assert_ne!(mark(&key), mark(&other));

    let planted = Planted::new(IndexPlant::Used);
    assert_eq!(
        fencing.cover_page(
            &mut client,
            &[(beside, interval(1, 1)), (key, interval(5, 6))]
        ),
        Ok(Progress::Done)
    );
    assert_eq!(planted.lookups(), [], "a batch of new keys asks no index");
    let request = fencing
        .cover_begin(&[(key, interval(4, 9))])
        .unwrap()
        .unwrap();
    assert_eq!(planted.lookups(), [Ok(())]);
    assert!(
        matches!(
            &request.op,
            Op::Write {
                next: Next::Edited { dropped, .. },
                ..
            } if dropped == &[1]
        ),
        "the write drops the key's chunk and keeps the rest of the page: {:?}",
        request.op
    );
    assert!(matches!(
        fencing.cover_end(request.run(&mut client)),
        Ok(Cover::Done)
    ));
    assert_eq!(
        decode_entries(&page(&store, 1).entries).unwrap(),
        [(beside, interval(1, 1)), (key, interval(4, 9))]
    );
    drop(planted);

    let planted = Planted::new(IndexPlant::OffByOne);
    assert_eq!(
        fencing.cover_page(&mut client, &[(key, interval(3, 12))]),
        Ok(Progress::Done)
    );
    assert_eq!(planted.lookups(), [Err(Unindexed::Mismatch)]);
    assert_eq!(
        decode_entries(&page(&store, 1).entries).unwrap(),
        [(beside, interval(1, 1)), (key, interval(3, 12))],
        "the pass found the stored chunk the write drops"
    );
    drop(planted);

    let planted = Planted::new(IndexPlant::Used);
    store.schedule(Arm::Timeout { commit: true });
    assert_eq!(
        fencing.cover_page(&mut client, &[(other, interval(1, 2))]),
        Ok(Progress::Unresolved)
    );
    assert_eq!(
        fencing.cover_page(&mut client, &[(other, interval(1, 2))]),
        Ok(Progress::Unresolved),
        "the stale basis fails its condition and the re-read becomes the basis"
    );
    assert_eq!(planted.lookups(), [Err(Unindexed::Miss)]);
    assert_eq!(
        fencing.cover_page(&mut client, &[(other, interval(1, 2))]),
        Ok(Progress::Done)
    );
    assert_eq!(planted.lookups(), [Err(Unindexed::Miss), Ok(())]);
    assert_eq!(
        decode_entries(&page(&store, 1).entries).unwrap(),
        [
            (beside, interval(1, 1)),
            (key, interval(3, 12)),
            (other, interval(1, 2))
        ]
    );
}
