use super::beat::{self, BeatError, BeatKey, Entry, Header};
use super::host::*;
use super::{DetectBounds, Failure, Liveness, ObservationGeneration, Suspicion};
use crate::failover::arbiter::{ArbiterBounds, Clock, FlipNomination, ObserverClass, Partition};
use crate::failover::assignment::hmac;
use crate::failover::evidence_tests::bounds as serving_bounds;
use crate::failover::records::{Host, ShardRecord};
use crate::failover::retire::Target;
use crate::failover::serving::{Event, Machine};
use crate::failover::sim::host;
use crate::failover::withhold::Withhold;
use crate::net::ownership::{ActivatedEpoch, Shard, ShardGeneration, VolumeState};
use crate::storage::store_tests::record as base_record;

const OWN: u64 = 1;
const OBS_BOOT: [u8; 16] = [0xAB; 16];
const H: u64 = 10;

pub(crate) fn bounds() -> WatchBounds {
    WatchBounds {
        detect: DetectBounds {
            h: H,
            d: 3,
            tau: 0,
            jitter: 5,
            peer_grace: 20,
            exit_windows: 2,
            dwell: 30,
            hosts: 12,
        },
        arbiter: ArbiterBounds {
            h: H,
            holder_grace: 5,
            k: 2,
            rounds: 3,
            clock_age: 1_000,
            dwell: 20,
            hosts: 8,
        },
        shards: 16,
        per_tick: 4,
        self_suspect: 3,
    }
}

fn record(shard: u32, owner: u64, attempts: u32) -> ShardRecord {
    ShardRecord {
        shard: Shard::new(shard).unwrap(),
        owner: host(owner),
        attempts,
        standby: Some(host(OWN)),
        ..base_record()
    }
}

fn placement() -> Vec<(Host, Partition)> {
    [
        (11, 1),
        (12, 1),
        (14, 4),
        (21, 2),
        (22, 3),
        (23, 1),
        (24, 5),
        (25, 6),
        (26, 2),
        (27, 2),
        (OWN, 9),
    ]
    .into_iter()
    .map(|(h, p)| (host(h), Partition(p)))
    .collect()
}

pub(crate) fn key(h: Host) -> Option<BeatKey> {
    Some(BeatKey::derive(&[h.get() as u8; 32]))
}

fn entry(shard: u32, read_age_us: Option<u64>) -> Entry {
    Entry {
        shard: Shard::new(shard).unwrap(),
        generation: ShardGeneration::new(3).unwrap(),
        epoch: ActivatedEpoch::new(2).unwrap(),
        volume: VolumeState::Active,
        report_age_us: 40,
        read_age_us,
    }
}

pub(crate) fn header(sender: u64, boot: u8, sequence: u64) -> Header {
    Header {
        host: host(sender),
        boot: [boot; 16],
        booted_at_us: u64::from(boot) * 100,
        sequence,
        ack: 0,
        io: sequence,
        completions: sequence,
        pending: 1,
        ack_boot: [0; 16],
        healthy: true,
    }
}

pub(crate) fn sealed(header: &Header, entries: &[Entry], receiver: u64) -> Vec<u8> {
    let mut out = vec![0; beat::MAX_LEN];
    let len = beat::encode(
        header,
        entries,
        host(receiver),
        &key(header.host).unwrap(),
        &mut out,
    )
    .unwrap();
    out.truncate(len);
    out
}

fn beat(sender: u64, boot: u8, sequence: u64, entries: &[Entry]) -> Vec<u8> {
    sealed(&header(sender, boot, sequence), entries, OWN)
}

fn acking(sender: u64, boot: u8, sequence: u64, ack: u64, entries: &[Entry]) -> Vec<u8> {
    sealed(
        &Header {
            ack,
            ack_boot: OBS_BOOT,
            ..header(sender, boot, sequence)
        },
        entries,
        OWN,
    )
}

pub(crate) fn clock(now: u64) -> Clock {
    Clock::Trusted { sampled_at: now }
}

fn tick(w: &mut Watch, t: u64) -> Option<RepairDemand> {
    w.tick(t, clock(t), true).unwrap()
}

fn valid(w: &Watch, n: &Nominated, t: u64) -> bool {
    w.revalidate(n, t, clock(t), true).is_some()
}

fn watch_with(records: &[ShardRecord], b: WatchBounds) -> Watch {
    let mut w = Watch::new(host(OWN), OBS_BOOT, b).unwrap();
    w.sync(records, &placement(), 0).unwrap();
    w
}

fn watch(records: &[ShardRecord]) -> Watch {
    watch_with(records, bounds())
}

fn dead(w: &Watch, h: u64) -> bool {
    matches!(w.liveness(host(h)), Some(Liveness::Dead(_)))
}

pub(crate) fn reply(request: ProbeRequest, prober: u64, reading: Reading) -> ProbeReply {
    ProbeReply {
        request,
        prober: host(prober),
        class: ObserverClass(prober as u32),
        reading,
    }
}

fn answer(w: &mut Watch, now: u64, reading: Reading) {
    let requests: Vec<_> = w.probes().collect();
    for r in requests {
        w.probe(reply(r, 21, reading), now).unwrap();
        w.probe(reply(r, 22, reading), now).unwrap();
    }
}

fn request_for(w: &Watch, suspect: u64) -> ProbeRequest {
    w.probes().find(|r| r.suspect == host(suspect)).unwrap()
}

pub(crate) const SILENT: Reading = Reading::Dead(Failure::Silent);

fn suspect() -> Watch {
    let mut w = watch(&[record(1, 11, 2)]);
    for t in [10, 20, 30] {
        tick(&mut w, t);
    }
    assert!(dead(&w, 11));
    w
}

#[test]
fn heartbeat_codec_matches_its_layout() {
    let h = Header {
        host: host(0x0102_0304_0506_0708),
        boot: [0xB0; 16],
        booted_at_us: 0x1111,
        sequence: 0x2222,
        ack: 0x3333,
        io: 0x4444,
        completions: 0x5555,
        pending: 0x6666,
        ack_boot: [0xC0; 16],
        healthy: true,
    };
    let e = Entry {
        shard: Shard::new(0x7777).unwrap(),
        generation: ShardGeneration::new(0x8888).unwrap(),
        epoch: ActivatedEpoch::new(0x9998).unwrap(),
        volume: VolumeState::Retired,
        report_age_us: 0xAAAA,
        read_age_us: Some(0xBBBB),
    };
    let mut expected = vec![0, 3, 1, 1, 1, 2, 3, 4, 5, 6, 7, 8];
    expected.extend([0xB0; 16]);
    for v in [0x1111u64, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666] {
        expected.extend(v.to_be_bytes());
    }
    expected.extend([0xC0; 16]);
    expected.extend(0x7777u32.to_be_bytes());
    expected.extend(0x8888u64.to_be_bytes());
    expected.extend(0x9998u32.to_be_bytes());
    expected.extend([2, 1]);
    expected.extend(0xAAAAu64.to_be_bytes());
    expected.extend(0xBBBBu64.to_be_bytes());
    let host_key = [0x08; 32];
    let k = BeatKey(hmac(&host_key, &[b"ebs-beat-key--01"]));
    assert_eq!(BeatKey::derive(&host_key).0, k.0);
    let receiver = OWN.to_be_bytes();
    expected.extend(hmac(&k.0, &[b"ebs-heartbeat-03", &receiver, &expected]));
    let mut out = vec![0; beat::MAX_LEN];
    let len = beat::encode(&h, &[e], host(OWN), &k, &mut out).unwrap();
    assert_eq!(&out[..len], &expected[..]);
    let (decoded, entries) = beat::decode(&expected, host(OWN), |_| Some(k)).unwrap();
    assert_eq!(decoded, h);
    assert_eq!(entries.collect::<Vec<_>>(), [e]);
    assert_eq!(
        beat::decode(&expected, host(2), |_| Some(k)).err(),
        Some(BeatError::Tag),
        "a heartbeat sealed for one receiver fails at another"
    );

    let many = [e; beat::MAX_ENTRIES + 1];
    let zero = Header { boot: [0; 16], ..h };
    let inactive = Entry {
        epoch: ActivatedEpoch::new(0).unwrap(),
        ..e
    };
    for (header, entries, room, refusal) in [
        (&h, &many[..], beat::MAX_LEN, BeatError::Count),
        (&h, &many[..1], len - 1, BeatError::Length),
        (&zero, &many[..1], len, BeatError::Field),
        (&h, &[inactive][..], len, BeatError::Field),
    ] {
        let mut out = vec![0xEE; room];
        assert_eq!(
            beat::encode(header, entries, host(OWN), &k, &mut out),
            Err(refusal)
        );
        assert!(out.iter().all(|&b| b == 0xEE), "{refusal:?} wrote bytes");
    }
}

#[test]
fn admission_rejects_before_state_change() {
    let mut w = watch(&[record(1, 11, 2)]);
    w.sent(1, 3).unwrap();
    w.heartbeat(&acking(11, 7, 5, 1, &[entry(1, Some(3))]), key, 4)
        .unwrap();
    assert_eq!(w.peer_read_at(), Some(0));
    tick(&mut w, 10);
    let before = w.snapshot();
    let k11 = key(host(11)).unwrap();

    let good = acking(11, 7, 6, 1, &[entry(1, Some(1))]);
    let mut version = good.clone();
    version[1] = 2;
    let mut tagged = good.clone();
    *tagged.last_mut().unwrap() ^= 1;
    let mut short = good.clone();
    short.pop();
    let mut health = good.clone();
    health[3] = 2;
    beat::seal(&mut health, &k11, host(OWN));
    let mut second = beat(11, 7, 6, &[entry(1, None), entry(2, None)]);
    second[beat::HEADER_LEN + beat::ENTRY_LEN + 16] = 9;
    beat::seal(&mut second, &k11, host(OWN));
    let mut absent = beat(11, 7, 6, &[entry(1, None)]);
    absent[beat::HEADER_LEN + beat::READ_AGE_AT + 7] = 1;
    beat::seal(&mut absent, &k11, host(OWN));
    let mut presence = beat(11, 7, 6, &[entry(1, Some(1))]);
    presence[beat::HEADER_LEN + 17] = 2;
    beat::seal(&mut presence, &k11, host(OWN));
    let mut count = good.clone();
    count[2] = 200;
    let elsewhere = sealed(&header(11, 7, 6), &[], 2);
    let unnamed = beat(99, 7, 6, &[]);
    let replayed = beat(11, 7, 5, &[entry(1, Some(0))]);
    let older = beat(11, 6, 9, &[]);
    let equal_stamp = sealed(
        &Header {
            boot: [9; 16],
            ..header(11, 7, 1)
        },
        &[],
        OWN,
    );
    let early_boot = beat(11, 8, 1, &[]);
    let refusals: [(&[u8], Option<BeatKey>, u64, WatchRefusal); 17] = [
        (
            &presence,
            Some(k11),
            12,
            WatchRefusal::Beat(BeatError::Field),
        ),
        (
            &version,
            Some(k11),
            12,
            WatchRefusal::Beat(BeatError::Version),
        ),
        (&tagged, Some(k11), 12, WatchRefusal::Beat(BeatError::Tag)),
        (&short, Some(k11), 12, WatchRefusal::Beat(BeatError::Length)),
        (&count, Some(k11), 12, WatchRefusal::Beat(BeatError::Count)),
        (&health, Some(k11), 12, WatchRefusal::Beat(BeatError::Field)),
        (&second, Some(k11), 12, WatchRefusal::Beat(BeatError::Field)),
        (&absent, Some(k11), 12, WatchRefusal::Beat(BeatError::Field)),
        (
            &elsewhere,
            Some(k11),
            12,
            WatchRefusal::Beat(BeatError::Tag),
        ),
        (
            &unnamed,
            key(host(99)),
            12,
            WatchRefusal::Beat(BeatError::Sender),
        ),
        (&good, None, 12, WatchRefusal::Beat(BeatError::Sender)),
        (&good, key(host(12)), 12, WatchRefusal::Beat(BeatError::Tag)),
        (&replayed, Some(k11), 12, WatchRefusal::Replay),
        (&older, Some(k11), 12, WatchRefusal::Replay),
        (&equal_stamp, Some(k11), 12, WatchRefusal::Replay),
        (&early_boot, Some(k11), 9, WatchRefusal::Time),
        (&early_boot, Some(k11), u64::MAX, WatchRefusal::Time),
    ];
    for (bytes, k, now, refusal) in refusals {
        assert_eq!(w.heartbeat(bytes, |_| k, now), Err(refusal));
        assert_eq!(w.snapshot(), before, "{refusal:?} changed the detector");
    }

    let smaller_nonce = sealed(
        &Header {
            boot: [2; 16],
            booted_at_us: 800,
            ..header(11, 2, 1)
        },
        &[],
        OWN,
    );
    w.heartbeat(&smaller_nonce, key, 12).unwrap();
    assert_ne!(w.snapshot(), before, "a larger stamp admits a new boot");
    w.heartbeat(&beat(11, 9, 1, &[]), key, 13).unwrap();
    let rebooted = w.snapshot();
    for old in [2, 7] {
        assert_eq!(
            w.heartbeat(&beat(11, old, 50, &[]), key, 14),
            Err(WatchRefusal::Replay),
            "boot {old} precedes the current boot"
        );
    }
    assert_eq!(w.snapshot(), rebooted);

    for t in [20, 30, 40, 50, 60] {
        tick(&mut w, t);
    }
    assert!(dead(&w, 11));
    assert_eq!(
        w.heartbeat(&beat(11, 3, 1, &[]), key, 61),
        Err(WatchRefusal::Replay),
        "an older boot without a fresh acknowledgment, as a recording carries"
    );
    w.sent(2, 55).unwrap();
    w.heartbeat(&acking(11, 3, 1, 2, &[]), key, 61).unwrap();
    assert!(
        !dead(&w, 11),
        "a boot with an older stamp is admitted once the current boot is suspected"
    );
}

/// A boot admitted with a lower stamp leaves the replay floor at the highest stamp admitted, so a recording of an
/// earlier boot, at its admitted sequence or a later one, changes nothing.
#[test]
fn a_lower_stamp_boot_keeps_earlier_boots_outside_the_replay_window() {
    let mut w = watch(&[record(1, 11, 2)]);
    w.heartbeat(&beat(11, 9, 1, &[]), key, 5).unwrap();
    for t in [10, 20, 30, 40] {
        tick(&mut w, t);
    }
    assert!(dead(&w, 11));
    w.sent(1, 35).unwrap();
    w.heartbeat(&acking(11, 3, 1, 1, &[]), key, 41).unwrap();
    assert!(
        !dead(&w, 11),
        "boot 3, stamp 300, follows boot 9, stamp 900"
    );
    let lowered = w.snapshot();
    for sequence in [1, 2] {
        assert_eq!(
            w.heartbeat(&beat(11, 9, sequence, &[]), key, 42),
            Err(WatchRefusal::Replay),
            "sequence {sequence} of boot 9 carries no fresh acknowledgment"
        );
        assert_eq!(w.snapshot(), lowered);
    }
    w.heartbeat(&beat(11, 3, 2, &[]), key, 43).unwrap();
    w.heartbeat(&beat(11, 10, 1, &[]), key, 44).unwrap();
    assert_ne!(
        w.snapshot(),
        lowered,
        "a stamp above every admitted one admits a new boot at once"
    );
}

#[test]
fn a_receipt_before_the_last_tick_is_admitted_and_a_new_boot_follows_the_last_close() {
    let mut w = watch(&[record(1, 11, 2)]);
    w.heartbeat(&beat(11, 1, 1, &[]), key, 1).unwrap();
    tick(&mut w, 10);
    tick(&mut w, 15);
    assert_eq!(
        w.heartbeat(&beat(11, 2, 1, &[]), key, 12),
        Ok(()),
        "a new boot received after the peer's last close and before the last tick"
    );
    assert_eq!(
        w.deadline(),
        Some(22),
        "the new boot's window opens at its receipt"
    );

    for boot in [1, 2] {
        let mut w = watch(&[record(1, 11, 2)]);
        w.heartbeat(&beat(11, 1, 1, &[]), key, 1).unwrap();
        for (sequence, deadline) in [(2, 10), (3, 20), (4, 30)] {
            tick(&mut w, deadline + 3);
            assert_eq!(
                w.heartbeat(&beat(11, boot, sequence, &[]), key, deadline + 1),
                Ok(()),
                "boot {boot} received between deadline {deadline} and its tick"
            );
        }
        tick(&mut w, 43);
        assert!(!dead(&w, 11), "boot {boot} sent in every window");
    }

    let mut w = watch(&[record(1, 11, 2)]);
    w.heartbeat(&beat(11, 1, 1, &[]), key, 1).unwrap();
    tick(&mut w, 10);
    tick(&mut w, 30);
    let before = w.snapshot();
    assert_eq!(
        w.heartbeat(&beat(11, 2, 1, &[]), key, 25),
        Err(WatchRefusal::Time),
        "a new boot received before an unobserved close"
    );
    assert_eq!(w.snapshot(), before);
    assert_eq!(
        w.heartbeat(&beat(11, 1, 2, &[]), key, 25),
        Ok(()),
        "the current boot received before that close"
    );
}

#[test]
fn window_thresholds_and_dwell() {
    let mut w = watch(&[record(1, 11, 2)]);
    w.heartbeat(&beat(11, 7, 1, &[]), key, 5).unwrap();
    tick(&mut w, 10);
    w.heartbeat(&beat(11, 7, 2, &[]), key, 15).unwrap();
    for t in [20, 30, 40] {
        tick(&mut w, t);
        assert!(!dead(&w, 11), "{t}: the empty count is below D");
    }
    tick(&mut w, 50);
    assert_eq!(
        w.liveness(host(11)),
        Some(Liveness::Dead(Suspicion {
            generation: ObservationGeneration(1),
            failure: Failure::Silent,
            since: 50,
        }))
    );
    for (seq, t) in [(3, 55), (4, 65)] {
        w.heartbeat(&beat(11, 7, seq, &[]), key, t).unwrap();
        tick(&mut w, t + 5);
        assert!(
            dead(&w, 11),
            "{}: exit needs E windows and the dwell",
            t + 5
        );
    }
    w.heartbeat(&beat(11, 7, 5, &[]), key, 75).unwrap();
    tick(&mut w, 80);
    assert_eq!(w.liveness(host(11)), Some(Liveness::Alive));

    let mut w = watch(&[record(1, 11, 2)]);
    for t in [10, 20, 30, 40, 50, 60, 70] {
        tick(&mut w, t);
    }
    w.heartbeat(&beat(11, 7, 1, &[]), key, 75).unwrap();
    tick(&mut w, 80);
    assert!(
        dead(&w, 11),
        "the dwell has passed with one non-empty window"
    );
    w.heartbeat(&beat(11, 7, 2, &[]), key, 85).unwrap();
    tick(&mut w, 90);
    assert_eq!(w.liveness(host(11)), Some(Liveness::Alive));

    let mut graced = bounds();
    graced.detect.peer_grace = 100;
    let mut w = watch_with(&[record(1, 11, 2)], graced);
    for t in (1..10).map(|n| n * H) {
        tick(&mut w, t);
        assert!(!dead(&w, 11), "{t}: inside new-peer grace");
    }
    tick(&mut w, 100);
    assert!(dead(&w, 11));
}

#[test]
fn an_alive_reading_rests_on_a_recent_heartbeat_of_the_current_generation() {
    let alive = |w: &Watch| w.liveness(host(11)) == Some(Liveness::Alive);
    let mut w = watch(&[record(1, 11, 2)]);
    assert!(
        alive(&w) && !w.hears(host(11), 0),
        "tracked and never heard"
    );
    assert!(!w.hears(host(99), 0), "untracked");
    w.heartbeat(&beat(11, 7, 1, &[]), key, 5).unwrap();
    assert!(w.hears(host(11), 5));
    // A new target opens a newer observation generation for its owner.
    w.sync(&[record(1, 11, 3)], &placement(), 6).unwrap();
    assert!(alive(&w) && !w.hears(host(11), 6), "retracked");
    assert_eq!(
        w.heartbeat(&beat(11, 7, 1, &[]), key, 7),
        Err(WatchRefusal::Replay)
    );
    assert!(!w.hears(host(11), 7), "a refused heartbeat backs nothing");
    w.heartbeat(&beat(11, 7, 2, &[]), key, 7).unwrap();
    assert!(w.hears(host(11), 7));
    w.sync(&[record(1, 11, 4)], &placement(), 8).unwrap();
    assert!(!w.hears(host(11), 8));
    w.heartbeat(&beat(11, 8, 1, &[]), key, 9).unwrap();
    assert!(
        alive(&w) && w.hears(host(11), 9),
        "the heartbeat that establishes a boot arrives in the generation the boot opens"
    );
    // A receipt time before the last one leaves the later time in place: h + jitter = 15 counts from 9.
    w.heartbeat(&beat(11, 8, 2, &[]), key, 4).unwrap();
    assert!(w.hears(host(11), 24) && !w.hears(host(11), 25));
    // The age reads the receipt times alone: ticks at 10 and 20 close one empty window and change no answer.
    for t in [10, 20] {
        tick(&mut w, t);
    }
    assert!(alive(&w) && w.hears(host(11), 24) && !w.hears(host(11), 25));

    // D stalled windows inside new-peer grace stand behind an ALIVE reading with a fresh heartbeat.
    let mut graced = bounds();
    graced.detect.peer_grace = 100;
    let mut w = watch_with(&[record(1, 11, 2)], graced);
    let flat = |sequence| Header {
        io: 1,
        completions: 1,
        ..header(11, 7, sequence)
    };
    for (sequence, t) in [(1, 5), (2, 15), (3, 25), (4, 35)] {
        assert!(w.hears(host(11), t - 1) == (sequence > 1), "{t}");
        w.heartbeat(&sealed(&flat(sequence), &[], OWN), key, t)
            .unwrap();
        tick(&mut w, t + 5);
    }
    assert!(alive(&w) && !w.hears(host(11), 40), "three stalled windows");
}

#[test]
fn idle_senders_progress_stalled_senders_read_gray_and_unhealthy_senders_read_declared() {
    let reads = |w: &Watch, kind: Failure| {
        matches!(
            w.liveness(host(11)),
            Some(Liveness::Dead(Suspicion { failure, .. })) if failure == kind
        )
    };
    let gray = |w: &Watch| reads(w, Failure::Gray);
    let run = |shape: fn(u64) -> Header| {
        let mut w = watch(&[record(1, 11, 2)]);
        for seq in 1..=6 {
            let t = seq * H;
            w.heartbeat(&sealed(&shape(seq), &[], OWN), key, t - 5)
                .unwrap();
            tick(&mut w, t);
        }
        w
    };
    let idle = run(|seq| Header {
        io: 0,
        completions: 0,
        pending: 0,
        ..header(11, 7, seq)
    });
    assert_eq!(idle.liveness(host(11)), Some(Liveness::Alive));
    let stalled = run(|seq| Header {
        io: 0,
        completions: 0,
        ..header(11, 7, seq)
    });
    assert!(gray(&stalled), "outstanding work without progress");
    let unhealthy = run(|seq| Header {
        healthy: false,
        ..header(11, 7, seq)
    });
    assert!(
        reads(&unhealthy, Failure::Declared),
        "a sender reporting itself unhealthy"
    );
}

#[test]
fn an_observer_pause_closes_its_windows_unobserved() {
    let run = |late: u64| {
        let mut w = watch(&[record(1, 11, 2)]);
        w.heartbeat(&beat(11, 7, 1, &[]), key, 5).unwrap();
        tick(&mut w, 10);
        tick(&mut w, 20);
        tick(&mut w, 20 + late);
        tick(&mut w, 30 + late);
        dead(&w, 11)
    };
    assert!(run(15), "a tick h + jitter after the last is observed");
    assert!(!run(16), "a later tick marks a pause");

    let retracked = |ticks: &[u64]| {
        let mut w = watch(&[record(1, 11, 2)]);
        tick(&mut w, 10);
        tick(&mut w, 20);
        w.sync(&[record(1, 11, 3)], &placement(), 28).unwrap();
        assert_eq!(w.deadline(), Some(38));
        for &t in ticks {
            tick(&mut w, t);
        }
        dead(&w, 11)
    };
    assert!(!retracked(&[38, 48]));
    assert!(
        retracked(&[38, 48, 58]),
        "a tick at the deadline the retrack moved observes its window"
    );
    assert!(
        retracked(&[43, 48, 58]),
        "a tick h + jitter after the retrack is observed"
    );
    assert!(
        !retracked(&[44, 54, 64]),
        "a later tick closes the retracked window unobserved"
    );
    assert!(retracked(&[44, 54, 64, 74]));

    let both = [record(1, 11, 2), record(2, 12, 2)];
    let mut w = watch(&both);
    tick(&mut w, 10);
    tick(&mut w, 20);
    w.sync(&[record(1, 11, 3), record(2, 12, 2)], &placement(), 39)
        .unwrap();
    tick(&mut w, 39);
    assert!(
        !dead(&w, 12),
        "a retrack of one peer leaves the pause on the other's window"
    );
    tick(&mut w, 49);
    assert!(dead(&w, 12) && !dead(&w, 11));

    let mut w = watch(&both);
    tick(&mut w, 10);
    tick(&mut w, 20);
    w.sync(&[record(1, 11, 2), record(2, 12, 3)], &placement(), 28)
        .unwrap();
    for t in [37, 38] {
        tick(&mut w, t);
    }
    assert!(
        !dead(&w, 11),
        "the window open across the pause is unobserved"
    );
    tick(&mut w, 47);
    assert!(dead(&w, 11));
    for t in [48, 57] {
        tick(&mut w, t);
    }
    assert!(!dead(&w, 12));
    tick(&mut w, 58);
    assert!(
        dead(&w, 12),
        "a window opened after the previous tick counts the pause from its start"
    );
}

#[test]
fn probe_veto_and_unknown() {
    let mut w = suspect();
    let open = w.probes().next().unwrap();
    assert_eq!(open.round, 1);
    for prober in [23, OWN, 11, 99] {
        assert_eq!(
            w.probe(reply(open, prober, SILENT), 30),
            Err(WatchRefusal::Prober)
        );
    }
    w.probe(reply(open, 21, SILENT), 30).unwrap();
    w.probe(reply(open, 22, SILENT), 30).unwrap();
    w.probe(reply(open, 24, Reading::Alive), 30).unwrap();
    assert_eq!(w.probes().next(), None, "the veto applies at once");
    let vetoed = w.snapshot();
    assert_eq!(
        w.probe(reply(open, 22, SILENT), 31),
        Err(WatchRefusal::Stale),
        "a reply of the vetoed cycle"
    );
    assert_eq!(w.snapshot(), vetoed);
    for t in [40, 50] {
        tick(&mut w, t);
        assert!(w.published().is_empty() && w.probes().next().is_none());
    }
    tick(&mut w, 60);
    let restarted = w.probes().next().unwrap();
    assert_eq!(restarted.round, 1);
    assert_ne!(restarted.cycle, open.cycle);
    let before = w.snapshot();
    assert_eq!(
        w.probe(reply(open, 21, SILENT), 60),
        Err(WatchRefusal::Stale)
    );
    assert_eq!(
        w.snapshot(),
        before,
        "the saved request of the vetoed cycle"
    );

    let mut w = suspect();
    let open = w.probes().next().unwrap();
    w.probe(reply(open, 21, SILENT), 30).unwrap();
    w.probe(reply(open, 22, SILENT), 30).unwrap();
    w.probe(reply(open, 22, Reading::Unknown), 30).unwrap();
    tick(&mut w, 40);
    assert!(w.published().is_empty(), "UNKNOWN does not count");
    let round2 = w.probes().next().unwrap();
    assert_eq!(round2.round, 2);
    w.probe(reply(round2, 21, SILENT), 40).unwrap();
    for reading in [SILENT, Reading::Unknown] {
        assert_eq!(
            w.probe(reply(open, 21, reading), 40),
            Err(WatchRefusal::Stale),
            "an earlier round cannot replace a later vote"
        );
    }
    w.probe(reply(open, 24, Reading::Unknown), 40).unwrap();
    w.probe(reply(open, 22, SILENT), 41).unwrap();
    tick(&mut w, 50);
    assert_eq!(
        w.published().len(),
        1,
        "a late reply of an earlier round counts, and UNKNOWN neither counts nor vetoes"
    );

    let mut w = suspect();
    for t in [40, 50, 60] {
        answer(&mut w, t - H, Reading::Unknown);
        tick(&mut w, t);
        assert!(
            w.published().is_empty(),
            "{t}: UNKNOWN never counts as DEAD"
        );
    }
    let spent = ProbeRequest { round: 3, ..open };
    assert!(
        w.probes().next().is_none(),
        "the judging window takes no replies"
    );
    tick(&mut w, 70);
    assert_eq!(
        w.liveness(host(11)),
        Some(Liveness::Unknown),
        "spent probe rounds read UNKNOWN"
    );
    tick(&mut w, 80);
    assert_eq!(w.probes().next().unwrap().round, 1, "probing restarts");
    assert_eq!(
        w.probe(reply(spent, 21, SILENT), 80),
        Err(WatchRefusal::Stale)
    );
}

#[test]
fn the_quorum_counts_partitions_and_keeps_room_for_them() {
    let mut w = suspect();
    let open = w.probes().next().unwrap();
    w.probe(reply(open, 26, SILENT), 30).unwrap();
    w.probe(reply(open, 27, SILENT), 30).unwrap();
    tick(&mut w, 40);
    assert!(w.published().is_empty(), "two votes from one partition");
    w.probe(reply(open, 22, SILENT), 40).unwrap();
    tick(&mut w, 50);
    assert_eq!(w.published().len(), 1, "a vote from a second partition");

    let mut narrow = bounds();
    narrow.arbiter.hosts = 2;
    let run = |first: [(u64, Reading); 2], then: &[u64]| {
        let mut w = watch_with(&[record(1, 11, 2)], narrow);
        for t in [10, 20, 30] {
            tick(&mut w, t);
        }
        let open = w.probes().next().unwrap();
        for (prober, reading) in first {
            w.probe(reply(open, prober, reading), 30).unwrap();
        }
        for &prober in then {
            w.probe(reply(open, prober, SILENT), 30).unwrap();
        }
        tick(&mut w, 40);
        w.published().len()
    };
    assert_eq!(
        run([(26, SILENT), (27, SILENT)], &[22]),
        1,
        "a new partition replaces a repeated one"
    );
    assert_eq!(
        run([(24, Reading::Unknown), (25, Reading::Unknown)], &[22, 21]),
        1,
        "DEAD replaces UNKNOWN"
    );

    let mut w = watch_with(&[record(1, 11, 2)], narrow);
    for t in [10, 20, 30] {
        tick(&mut w, t);
    }
    let open = w.probes().next().unwrap();
    w.probe(reply(open, 21, SILENT), 30).unwrap();
    w.probe(reply(open, 25, SILENT), 30).unwrap();
    assert_eq!(
        w.probe(reply(open, 22, SILENT), 30),
        Err(WatchRefusal::Prober),
        "the vote record is full of distinct partitions"
    );
    w.probe(reply(open, 24, Reading::Alive), 30).unwrap();
    assert_eq!(w.probes().next(), None, "ALIVE vetoes a full record");
}

#[test]
fn a_reply_from_an_earlier_generation_is_stale() {
    let mut w = suspect();
    let open = w.probes().next().unwrap();
    w.sync(&[record(1, 11, 3)], &placement(), 30).unwrap();
    for t in [40, 50, 60] {
        tick(&mut w, t);
    }
    let reopened = w.probes().next().unwrap();
    assert_eq!(reopened.round, open.round);
    assert_ne!(reopened.generation, open.generation);
    let before = w.snapshot();
    let saved = ProbeRequest {
        cycle: reopened.cycle,
        ..open
    };
    assert_eq!(
        w.probe(reply(saved, 21, SILENT), 60),
        Err(WatchRefusal::Stale)
    );
    assert_eq!(w.snapshot(), before);
}

type SyncFn = fn(&mut Watch, &[ShardRecord], &[(Host, Partition)], u64) -> Result<(), WatchRefusal>;
type BeatFn = fn(&mut Watch, &[u8], fn(Host) -> Option<BeatKey>, u64) -> Result<(), WatchRefusal>;
type TickFn = fn(&mut Watch, u64, Clock, bool) -> Result<Option<RepairDemand>, WatchRefusal>;
type CheckFn = fn(&Watch, &Nominated, u64, Clock, bool) -> Option<Revalidated>;

#[test]
fn publishes_nomination_only() {
    let _: fn(Host, [u8; 16], WatchBounds) -> Result<Watch, WatchRefusal> = Watch::new;
    let _: SyncFn = Watch::sync;
    let _: BeatFn = Watch::heartbeat;
    let _: fn(&mut Watch, ProbeReply, u64) -> Result<(), WatchRefusal> = Watch::probe;
    let _: TickFn = Watch::tick;
    let _: CheckFn = Watch::revalidate;
    let _: fn(&Watch) -> &[Nominated] = Watch::published;

    let mut records: Vec<_> = (1..=6).map(|s| record(s, 11, s + 1)).collect();
    records.push(ShardRecord {
        standby: Some(host(14)),
        ..record(7, 12, 1)
    });
    records.push(ShardRecord {
        standby: None,
        ..record(8, 12, 1)
    });
    let mut b = bounds();
    b.self_suspect = 4;
    let mut w = watch_with(&records, b);
    for t in [10, 20, 30] {
        tick(&mut w, t);
    }
    assert!(dead(&w, 12) && dead(&w, 14));
    let probed: Vec<_> = w.probes().map(|r| r.suspect.get()).collect();
    assert_eq!(probed, [11, 12, 14], "every suspect is probed");
    answer(&mut w, 30, SILENT);
    tick(&mut w, 40);
    let first = w.published().to_vec();
    assert_eq!(w.census().nominations, 4, "the first capped batch");
    answer(&mut w, 40, SILENT);
    tick(&mut w, 50);
    let second = w.published().to_vec();
    assert_eq!(w.census().nominations, 6, "the deferred targets add on");
    answer(&mut w, 50, SILENT);
    tick(&mut w, 60);
    assert_eq!((first.len(), second.len()), (4, 2));
    assert!(w.published().is_empty(), "each target is nominated once");
    assert_eq!(w.census().nominations, 6, "an empty tick keeps the count");
    for (n, r) in first.iter().chain(&second).zip(&records) {
        assert_eq!(n.shard, r.shard);
        assert_eq!(
            n.nomination,
            FlipNomination {
                target: Target::of(r)
            }
        );
        assert!(valid(&w, n, 79));
        assert_eq!(
            w.revalidate(n, 65, clock(65), true),
            Some(Revalidated {
                shard: r.shard,
                target: Target::of(r),
                until_us: 75,
            }),
            "the witness expires one 10 µs window after its mint"
        );
        assert!(!valid(&w, n, 80), "the evidence is two windows old");
        assert!(!valid(&w, n, 59), "a time before the last close");
        assert!(w.revalidate(n, 60, Clock::Untrusted, true).is_none());
        assert!(w.revalidate(n, 60, clock(60), false).is_none());
    }

    w.sync(&records[1..], &placement(), 60).unwrap();
    assert!(dead(&w, 11), "losing a target keeps the owner's evidence");
    assert!(!valid(&w, &first[0], 60), "the dropped target");
    assert!(valid(&w, &first[1], 60));

    let mut bumped = records[1..].to_vec();
    bumped[0].attempts += 1;
    w.sync(&bumped, &placement(), 60).unwrap();
    assert!(!valid(&w, &first[1], 60), "the record's E changed");
    assert!(
        !valid(&w, &first[2], 60),
        "the retracked owner opened a newer generation"
    );
    for t in [70, 80, 90] {
        tick(&mut w, t);
        assert!(
            w.published().is_empty(),
            "{t}: evidence from before the change does not nominate"
        );
    }
    answer(&mut w, 90, SILENT);
    tick(&mut w, 100);
    let mut renewed = w.published().to_vec();
    answer(&mut w, 100, SILENT);
    tick(&mut w, 110);
    renewed.extend_from_slice(w.published());
    let targets: Vec<_> = renewed.iter().map(|n| n.nomination.target).collect();
    let expected: Vec<_> = bumped[..5].iter().map(Target::of).collect();
    assert_eq!(targets, expected, "every target republishes");
    assert_eq!(
        w.census().nominations,
        11,
        "a republished target counts again"
    );
    let old = first[2];
    let new = renewed[1];
    assert_eq!((old.shard, old.nomination), (new.shard, new.nomination));
    assert!(new.generation > old.generation);
    assert!(!valid(&w, &old, 110) && valid(&w, &new, 110));
}

#[test]
fn the_tick_budget_rotates_across_owners() {
    let mut records: Vec<_> = (1..=6).map(|s| record(s, 11, 1)).collect();
    records.push(record(7, 12, 1));
    let mut b = bounds();
    b.per_tick = 2;
    let mut w = watch_with(&records, b);
    for t in [10, 20, 30] {
        tick(&mut w, t);
    }
    let mut shards = Vec::new();
    for t in [40, 50] {
        answer(&mut w, t - H, SILENT);
        tick(&mut w, t);
        shards.extend(w.published().iter().map(|n| n.shard.get()));
    }
    assert!(
        shards.contains(&7),
        "the second owner publishes within two ticks"
    );
}

#[test]
fn a_quorum_in_the_last_round_holds_its_nomination() {
    let mut w = suspect();
    tick(&mut w, 40);
    tick(&mut w, 50);
    answer(&mut w, 50, SILENT);
    assert_eq!(w.probes().next().unwrap().round, 3);
    tick(&mut w, 60);
    let n = w.published().to_vec();
    assert_eq!(n.len(), 1);
    for t in [70, 80, 90] {
        answer(&mut w, t - H, SILENT);
        tick(&mut w, t);
        assert!(dead(&w, 11) && valid(&w, &n[0], t), "{t}: the cycle holds");
    }
    let held = w.probes().next().unwrap();
    assert_eq!(held.round, 3);
    w.probe(reply(held, 24, Reading::Alive), 90).unwrap();
    assert!(
        !valid(&w, &n[0], 90),
        "a veto still applies to a held cycle"
    );

    let mut single = bounds();
    single.arbiter.rounds = 1;
    let records: Vec<_> = (1..=6).map(|s| record(s, 11, 1)).collect();
    let mut w = watch_with(&records, single);
    for t in [10, 20, 30] {
        tick(&mut w, t);
    }
    answer(&mut w, 30, SILENT);
    tick(&mut w, 40);
    assert_eq!(w.published().len(), 4);
    answer(&mut w, 40, SILENT);
    tick(&mut w, 50);
    assert_eq!(
        w.published().len(),
        2,
        "a full outbox waits with the quorum held"
    );
}

#[test]
fn held_votes_expire_and_unknown_withdraws_them() {
    let mut w = suspect();
    answer(&mut w, 30, SILENT);
    tick(&mut w, 40);
    let n = w.published().to_vec();
    assert!(valid(&w, &n[0], 40));
    let held = w.probes().next().unwrap();
    w.probe(reply(held, 21, Reading::Unknown), 41).unwrap();
    assert!(!valid(&w, &n[0], 41), "one DEAD vote remains");
    w.probe(reply(held, 21, SILENT), 42).unwrap();
    assert!(valid(&w, &n[0], 42));
    for t in [50, 60, 70] {
        tick(&mut w, t);
    }
    assert!(
        !valid(&w, &n[0], 70),
        "votes older than the probe rounds lapse"
    );
}

#[test]
fn a_veto_withdraws_published_targets_and_a_new_quorum_republishes() {
    let mut w = suspect();
    answer(&mut w, 30, SILENT);
    tick(&mut w, 40);
    let first = w.published().to_vec();
    assert_eq!(first.len(), 1);
    tick(&mut w, 50);
    let held = w.probes().next().unwrap();
    w.probe(reply(held, 24, Reading::Alive), 50).unwrap();
    assert!(!valid(&w, &first[0], 50), "the veto withdraws the target");
    for t in [60, 70, 80] {
        tick(&mut w, t);
    }
    answer(&mut w, 80, SILENT);
    tick(&mut w, 90);
    assert_eq!(w.published().to_vec(), first);
    assert!(valid(&w, &first[0], 90));
}

#[test]
fn an_unobserved_close_withdraws_and_restarts_the_cycle() {
    let mut w = suspect();
    answer(&mut w, 30, SILENT);
    tick(&mut w, 40);
    let first = w.published().to_vec();
    tick(&mut w, 70);
    assert!(dead(&w, 11));
    assert!(w.published().is_empty());
    assert!(!valid(&w, &first[0], 70), "votes from before the pause");
    assert_eq!(w.probes().next().unwrap().round, 1);
    answer(&mut w, 70, SILENT);
    tick(&mut w, 80);
    assert_eq!(w.published().to_vec(), first);
    assert!(valid(&w, &first[0], 80));
}

#[test]
fn an_untrusted_clock_or_unhealthy_observer_publishes_nothing() {
    let mut w = suspect();
    answer(&mut w, 30, SILENT);
    w.tick(40, Clock::Untrusted, true).unwrap();
    assert!(w.published().is_empty());
    w.tick(50, clock(50), false).unwrap();
    assert!(w.published().is_empty());
    tick(&mut w, 60);
    assert_eq!(w.published().len(), 1);
}

#[test]
fn a_target_republishes_after_its_owner_recovers_or_reboots() {
    let mut w = suspect();
    answer(&mut w, 30, SILENT);
    tick(&mut w, 40);
    let first = w.published().to_vec();
    for (seq, t) in [(1, 45), (2, 55), (3, 65)] {
        w.heartbeat(&beat(11, 7, seq, &[]), key, t).unwrap();
        tick(&mut w, t + 5);
    }
    assert_eq!(w.liveness(host(11)), Some(Liveness::Alive));
    for t in [80, 90, 100] {
        tick(&mut w, t);
    }
    assert!(dead(&w, 11));
    assert!(
        !valid(&w, &first[0], 100),
        "a nomination from the earlier suspicion needs a new quorum"
    );
    answer(&mut w, 100, SILENT);
    tick(&mut w, 110);
    assert_eq!(w.published().to_vec(), first);

    w.heartbeat(&beat(11, 8, 1, &[]), key, 111).unwrap();
    assert!(
        !valid(&w, &first[0], 111),
        "a new boot withdraws the target"
    );
    for t in [120, 130, 140, 150, 160] {
        tick(&mut w, t);
    }
    answer(&mut w, 160, SILENT);
    tick(&mut w, 170);
    let rebooted = w.published().to_vec();
    assert_eq!(rebooted.len(), 1);
    assert!(rebooted[0].generation > first[0].generation);
}

#[test]
fn record_read_age_admitted_and_exported() {
    let records = [record(1, 11, 2), record(2, 12, 2)];
    let mut w = watch(&records);
    let mut sender = Machine::new(serving_bounds(), &crate::storage::next_session());
    sender.step(Event::Refresh { at: 400 });
    let age = sender.read_age(700);
    assert_eq!(age, Some(300));
    w.sent(1, 800).unwrap();
    w.heartbeat(&acking(11, 7, 1, 1, &[entry(1, age)]), key, 900)
        .unwrap();
    assert_eq!(
        w.peer_read_at(),
        Some(500),
        "the send time of the acknowledged heartbeat minus the age"
    );
    w.heartbeat(&acking(11, 7, 2, 9, &[entry(1, Some(1))]), key, 950)
        .unwrap();
    assert_eq!(w.peer_read_at(), Some(500), "an unknown acknowledgment");

    w.sent(2, 1_000).unwrap();
    w.heartbeat(&beat(12, 7, 1, &[]), key, 1_005).unwrap();
    let mut altered = acking(12, 7, 2, 2, &[entry(2, Some(100))]);
    altered[beat::HEADER_LEN + beat::READ_AGE_AT + 7] ^= 0x40;
    let untouched = w.snapshot();
    assert_eq!(
        w.heartbeat(&altered, key, 1_010),
        Err(WatchRefusal::Beat(BeatError::Tag))
    );
    assert_eq!(w.snapshot(), untouched);
    let three = [
        entry(1, Some(500)),
        entry(2, Some(100)),
        entry(3, Some(300)),
    ];
    w.heartbeat(&acking(12, 7, 2, 2, &three), key, 1_010)
        .unwrap();
    assert_eq!(w.peer_read_at(), Some(900), "the newest read of the three");
    w.heartbeat(&acking(12, 7, 3, 2, &[entry(2, Some(5_000))]), key, 1_040)
        .unwrap();
    assert_eq!(w.peer_read_at(), Some(900), "an age above the send time");
    w.heartbeat(&acking(11, 8, 1, 2, &[entry(1, Some(50))]), key, 1_050)
        .unwrap();
    assert_eq!(
        w.peer_read_at(),
        Some(950),
        "a new boot's first heartbeat counts with a fresh acknowledgment"
    );
    for s in 3..=5 {
        w.sent(s, 2_000 + s).unwrap();
    }
    w.heartbeat(&acking(12, 7, 4, 2, &[entry(2, Some(1))]), key, 2_010)
        .unwrap();
    assert_eq!(
        w.peer_read_at(),
        Some(950),
        "the acknowledged heartbeat left the last D"
    );

    let mut serving = Machine::new(serving_bounds(), &crate::storage::next_session());
    serving.step(w.peer_event());
    assert_eq!(serving.withhold().peer_read_at(), Some(950));

    let mut w = watch(&records);
    w.sent(1, 10).unwrap();
    w.heartbeat(&acking(11, 7, 1, 1, &[entry(1, None)]), key, 20)
        .unwrap();
    assert_eq!(w.peer_read_at(), None);
    assert_eq!(w.peer_event(), Event::Peer { read_at: None });
    assert_eq!(Withhold::default().read_age(5), None);
    let mut refreshed = Withhold::default();
    refreshed.refresh(10);
    assert_eq!(refreshed.read_age(9), None, "a time before the refresh");
}

#[test]
fn partition_event_against_self_suspicion_threshold() {
    let records = [record(1, 11, 2), record(2, 12, 2), record(3, 14, 2)];
    for (threshold, nominates) in [(3, true), (2, false)] {
        let mut b = bounds();
        b.self_suspect = threshold;
        let mut w = watch_with(&records, b);
        let mut repair = None;
        let mut shards = Vec::new();
        for (seq, t) in (1..=5).map(|n| (n, n * H)) {
            w.heartbeat(&beat(14, 7, seq, &[entry(3, None)]), key, t - 5)
                .unwrap();
            answer(&mut w, t - H, SILENT);
            repair = tick(&mut w, t).or(repair);
            shards.extend(w.published().iter().map(|n| n.shard.get()));
        }
        assert!(dead(&w, 11) && dead(&w, 12) && !dead(&w, 14));
        if nominates {
            assert_eq!(repair, None);
            assert_eq!(shards, [1, 2]);
        } else {
            assert_eq!(
                repair,
                Some(RepairDemand {
                    suspects: 2,
                    until: 70
                })
            );
            assert!(shards.is_empty());
        }
    }
}

#[test]
fn a_vetoed_suspect_leaves_the_count_until_new_dead_evidence() {
    let mut b = bounds();
    b.self_suspect = 2;
    let mut w = watch_with(&[record(1, 11, 2), record(2, 12, 2)], b);
    for t in [10, 20] {
        tick(&mut w, t);
    }
    assert_eq!(
        tick(&mut w, 30),
        Some(RepairDemand {
            suspects: 2,
            until: 50
        })
    );
    w.probe(reply(request_for(&w, 11), 24, Reading::Alive), 30)
        .unwrap();
    assert_eq!(
        tick(&mut w, 40),
        Some(RepairDemand {
            suspects: 1,
            until: 50
        })
    );
    for t in [50, 60, 70] {
        assert_eq!(tick(&mut w, t), None, "{t}: the veto outlasts its phase");
    }
    w.probe(reply(request_for(&w, 11), 21, SILENT), 70).unwrap();
    assert_eq!(
        tick(&mut w, 80),
        Some(RepairDemand {
            suspects: 2,
            until: 100
        })
    );

    let mut w = watch_with(&[record(1, 11, 2), record(2, 12, 2)], b);
    let mut last = None;
    for t in [10, 20, 30, 40, 50, 60, 70] {
        last = tick(&mut w, t);
    }
    assert_eq!(w.liveness(host(11)), Some(Liveness::Unknown));
    assert_eq!(
        last,
        Some(RepairDemand {
            suspects: 2,
            until: 90
        }),
        "a spent probe cycle keeps its suspicion counted"
    );
}

#[test]
fn an_untargeted_suspect_is_probed_and_vetoable() {
    let records = [
        record(1, 11, 2),
        ShardRecord {
            standby: Some(host(14)),
            ..record(2, 12, 2)
        },
    ];
    let mut b = bounds();
    b.self_suspect = 2;
    let mut w = watch_with(&records, b);
    for (seq, t) in [(1, 10), (2, 20), (3, 30)] {
        w.heartbeat(&beat(14, 7, seq, &[]), key, t - 5).unwrap();
        tick(&mut w, t);
    }
    w.probe(reply(request_for(&w, 12), 24, Reading::Alive), 30)
        .unwrap();
    w.heartbeat(&beat(14, 7, 4, &[]), key, 35).unwrap();
    answer(&mut w, 30, SILENT);
    assert_eq!(
        tick(&mut w, 40),
        Some(RepairDemand {
            suspects: 1,
            until: 50
        }),
        "the dwell from the two suspects at 30 holds"
    );
    assert!(w.published().is_empty(), "the dwell suppresses owner 11");
    w.heartbeat(&beat(14, 7, 5, &[]), key, 45).unwrap();
    assert_eq!(tick(&mut w, 50), None);
    let shards: Vec<_> = w.published().iter().map(|n| n.shard.get()).collect();
    assert_eq!(
        shards,
        [1],
        "the vetoed untargeted suspect left the count, so owner 11 nominates at the deadline"
    );
}

#[test]
fn self_suspicion_withdraws_revalidation_of_held_nominations() {
    let mut b = bounds();
    b.self_suspect = 2;
    let mut w = watch_with(&[record(1, 11, 2), record(2, 12, 2)], b);
    let mut published = Vec::new();
    for (seq, t) in (1..=7).map(|n| (n, n * H)) {
        if t <= 40 {
            w.heartbeat(&beat(12, 7, seq, &[]), key, t - 5).unwrap();
        }
        answer(&mut w, t - H, SILENT);
        tick(&mut w, t);
        published.extend(w.published().iter().copied());
        if t == 60 {
            assert!(valid(&w, &published[0], t), "below the threshold");
        }
    }
    assert_eq!(published.len(), 1);
    assert!(dead(&w, 12));
    assert!(
        !valid(&w, &published[0], 70),
        "the observer suspects itself"
    );

    let mut short = bounds();
    short.self_suspect = 2;
    short.arbiter.dwell = H;
    let mut w = watch_with(&[record(1, 11, 2), record(2, 12, 2)], short);
    for (seq, t) in (1..=6).map(|n| (n, n * H)) {
        if t <= 40 {
            w.heartbeat(&beat(12, 7, seq, &[]), key, t - 5).unwrap();
        }
        answer(&mut w, t - H, SILENT);
        tick(&mut w, t);
        published.extend(w.published().iter().copied());
    }
    let n = published[1];
    answer(&mut w, 60, SILENT);
    tick(&mut w, 70);
    assert!(!valid(&w, &n, 75), "inside the dwell");
    assert!(
        !valid(&w, &n, 82),
        "the last tick's self-suspicion holds past its dwell until the next tick"
    );
}

/// Hosts 11, 267 and 523 have equal keys modulo 256, and the records alternate between them, so each lookup after
/// the first starts at another host's roster place. The sync tracks each host exactly once, in first-record order,
/// and its refusals leave the detector unchanged.
#[test]
fn sync_tracks_hosts_with_equal_key_residues_once_in_first_appearance_order() {
    let places: Vec<_> = [(11, 1), (267, 2), (523, 3), (21, 4), (OWN, 9)]
        .into_iter()
        .map(|(h, p)| (host(h), Partition(p)))
        .collect();
    let owners = [11, 267, 523, 267, 11, 523, 11];
    let records: Vec<_> = (1..)
        .zip(owners)
        .map(|(shard, owner)| record(shard, owner, 0))
        .collect();
    let mut w = Watch::new(host(OWN), OBS_BOOT, bounds()).unwrap();
    w.sync(&records, &places, 0).unwrap();
    for h in [11, 267, 523] {
        assert_eq!(w.liveness(host(h)), Some(Liveness::Alive), "host {h}");
    }
    assert_eq!(w.liveness(host(21)), None, "an unnamed placement entry");
    for t in [10, 20, 30] {
        tick(&mut w, t);
    }
    let probed: Vec<_> = w
        .probes()
        .map(|r| (r.suspect.get(), r.generation.0))
        .collect();
    assert_eq!(probed, [(11, 1), (267, 2), (523, 3)]);

    let before = w.snapshot();
    let mut unplaced = records.clone();
    unplaced.push(record(8, 779, 0));
    assert_eq!(
        w.sync(&unplaced, &places, 30),
        Err(WatchRefusal::Placement),
        "host 779 shares the residue and has no placement"
    );
    let mut repeated = records.clone();
    repeated.push(record(2, 21, 0));
    assert_eq!(
        w.sync(&repeated, &places, 30),
        Err(WatchRefusal::Duplicate),
        "shard 2 repeats with five records between its two uses"
    );
    assert_eq!(w.snapshot(), before);
    w.sync(&records[..2], &places, 30).unwrap();
    assert_eq!(w.liveness(host(523)), None, "a host no record names");
}

type SyncCase<'a> = (
    &'a [ShardRecord],
    &'a [(Host, Partition)],
    u64,
    WatchRefusal,
);

#[test]
fn sync_and_tick_refusals_leave_the_detector_unchanged() {
    let mut w = watch(&[record(1, 11, 2)]);
    tick(&mut w, 10);
    let before = w.snapshot();
    let many: Vec<_> = (1..=17).map(|s| record(s, 11, 1)).collect();
    let mut wide = placement();
    wide.extend((30..32).map(|h| (host(h), Partition(9))));
    let mut twice = placement();
    twice[2] = (host(11), Partition(7));
    let cases: [SyncCase; 7] = [
        (&many, &placement(), 10, WatchRefusal::Shards),
        (&[record(1, 11, 2)], &wide, 10, WatchRefusal::Placement),
        (
            &[record(1, 11, 2), record(1, 12, 2)],
            &placement(),
            10,
            WatchRefusal::Duplicate,
        ),
        (&[record(1, 11, 2)], &twice, 10, WatchRefusal::Duplicate),
        (
            &[record(1, 13, 2)],
            &placement(),
            10,
            WatchRefusal::Placement,
        ),
        (&[record(1, 11, 2)], &placement(), 9, WatchRefusal::Time),
        (
            &[record(1, 11, 2)],
            &placement(),
            u64::MAX,
            WatchRefusal::Time,
        ),
    ];
    for (records, placement, now, refusal) in cases {
        assert_eq!(w.sync(records, placement, now), Err(refusal));
        assert_eq!(w.snapshot(), before, "{refusal:?} changed the detector");
    }
    for now in [9, u64::MAX] {
        assert_eq!(w.tick(now, clock(now), true), Err(WatchRefusal::Time));
        assert_eq!(w.snapshot(), before);
    }
    for records in [&[record(1, 11, 2)][..], &[]] {
        let mut w = watch(records);
        tick(&mut w, 10);
        tick(&mut w, 15);
        let before = w.snapshot();
        assert_eq!(
            w.sync(&[record(1, 11, 3)], &placement(), 12),
            Err(WatchRefusal::Time),
            "a sync before the last tick"
        );
        assert_eq!(w.snapshot(), before);
    }
    let mut long = bounds();
    long.arbiter.dwell = 1_000;
    let mut late = Watch::new(host(OWN), OBS_BOOT, long).unwrap();
    assert_eq!(
        late.sync(&[record(1, 11, 2)], &placement(), u64::MAX - 500),
        Err(WatchRefusal::Time),
        "the dwell deadline from now overflows"
    );

    w.sync(&[record(2, 12, 2)], &placement(), 10).unwrap();
    assert_eq!(
        w.heartbeat(&beat(11, 7, 1, &[]), key, 11),
        Err(WatchRefusal::Beat(BeatError::Sender)),
        "a dropped host"
    );

    let base = bounds();
    let mut variants = [base; 8];
    variants[0].arbiter.rounds = u32::MAX;
    variants[1].arbiter.k = MAX_PROBERS + 1;
    variants[1].arbiter.hosts = MAX_PROBERS + 1;
    variants[2].shards = 0;
    variants[3].per_tick = 0;
    variants[4].self_suspect = 1;
    variants[5].self_suspect = base.detect.hosts + 1;
    variants[6].arbiter.h = H + 1;
    variants[6].arbiter.dwell = H + 1;
    let wide = u64::MAX / u64::from(base.arbiter.rounds);
    variants[7].detect.h = wide;
    variants[7].detect.dwell = wide;
    variants[7].arbiter.h = wide;
    variants[7].arbiter.dwell = wide;
    for v in variants {
        assert_eq!(v.validate().err(), Some(WatchRefusal::Bounds), "{v:?}");
    }
    let mut edge = base;
    edge.arbiter.rounds = u32::MAX - 1;
    assert!(edge.validate().is_ok());
    let mut edge = variants[7];
    edge.detect.jitter = 0;
    assert!(
        edge.validate().is_ok(),
        "a vote lifetime of the whole clock range fits"
    );
    assert_eq!(
        Watch::new(host(OWN), [0; 16], base).err(),
        Some(WatchRefusal::Beat(BeatError::Field)),
        "a zero observer boot equals the acknowledgment of a peer that received nothing"
    );

    let mut w = suspect();
    let open = w.probes().next().unwrap();
    w.probe(reply(open, 21, SILENT), 30).unwrap();
    let mut moved = placement();
    moved[3].1 = Partition(8);
    w.sync(&[record(1, 11, 2)], &moved, 30).unwrap();
    assert_eq!(
        w.probe(reply(open, 22, SILENT), 30),
        Err(WatchRefusal::Stale),
        "a prober that moved partition ends the cycle"
    );
    let mut w = suspect();
    let open = w.probes().next().unwrap();
    let mut owner_moved = placement();
    owner_moved[0].1 = Partition(8);
    w.sync(&[record(1, 11, 2)], &owner_moved, 30).unwrap();
    assert_eq!(
        w.probe(reply(open, 21, SILENT), 30),
        Err(WatchRefusal::Stale),
        "a partition change opens a newer observation generation"
    );
}

fn classed(request: ProbeRequest, prober: u64, class: u32, reading: Reading) -> ProbeReply {
    ProbeReply {
        class: ObserverClass(class),
        ..reply(request, prober, reading)
    }
}

const GRAY: Reading = Reading::Dead(Failure::Gray);

#[test]
fn gray_votes_need_a_second_class_and_eviction_keeps_one() {
    let mut w = suspect();
    let open = w.probes().next().unwrap();
    w.probe(classed(open, 21, 1, GRAY), 30).unwrap();
    w.probe(classed(open, 22, 1, GRAY), 30).unwrap();
    tick(&mut w, 40);
    assert!(w.published().is_empty(), "two partitions of one class");
    w.probe(classed(open, 22, 2, GRAY), 40).unwrap();
    tick(&mut w, 50);
    assert_eq!(w.published().len(), 1, "a second class corroborates");

    let mut narrow = bounds();
    narrow.arbiter.hosts = 2;
    let mut w = watch_with(&[record(1, 11, 2)], narrow);
    for t in [10, 20, 30] {
        tick(&mut w, t);
    }
    let open = w.probes().next().unwrap();
    w.probe(classed(open, 26, 2, GRAY), 30).unwrap();
    w.probe(classed(open, 27, 1, GRAY), 30).unwrap();
    assert_eq!(
        w.probe(classed(open, 24, 3, Reading::Unknown), 30),
        Err(WatchRefusal::Prober),
        "UNKNOWN takes no counting vote's place"
    );
    w.probe(classed(open, 22, 1, GRAY), 30).unwrap();
    tick(&mut w, 40);
    assert_eq!(
        w.published().len(),
        1,
        "the evicted vote is the one whose class the new vote keeps"
    );

    for second in [24, 26] {
        let mut w = watch_with(&[record(1, 11, 2)], narrow);
        for t in [10, 20, 30] {
            tick(&mut w, t);
        }
        let open = w.probes().next().unwrap();
        w.probe(classed(open, 21, 1, GRAY), 30).unwrap();
        w.probe(classed(open, 22, 1, GRAY), 30).unwrap();
        tick(&mut w, 40);
        assert!(w.published().is_empty(), "two partitions of one class");
        let open = w.probes().next().unwrap();
        assert_eq!(
            w.probe(classed(open, 25, 1, GRAY), 40),
            Err(WatchRefusal::Prober),
            "a third vote of the same class takes no place"
        );
        w.probe(classed(open, second, 2, GRAY), 40).unwrap();
        tick(&mut w, 50);
        assert_eq!(
            w.published().len(),
            1,
            "prober {second} of a second class takes the place of a vote whose class another keeps"
        );
    }
}

#[test]
fn an_alive_reply_vetoes_in_the_judging_window_and_after_a_later_vote() {
    let mut w = suspect();
    let open = w.probes().next().unwrap();
    for t in [40, 50, 60] {
        tick(&mut w, t);
    }
    assert!(
        w.probes().next().is_none(),
        "the judging window issues nothing"
    );
    assert_eq!(
        w.probe(reply(ProbeRequest { round: 3, ..open }, 21, SILENT), 60),
        Err(WatchRefusal::Stale),
        "DEAD in the judging window"
    );
    w.probe(reply(open, 24, Reading::Alive), 60).unwrap();
    tick(&mut w, 70);
    assert_eq!(
        tick(&mut w, 80),
        None,
        "the veto survives the judging window"
    );

    let mut w = suspect();
    let open = w.probes().next().unwrap();
    tick(&mut w, 40);
    let round2 = w.probes().next().unwrap();
    w.probe(reply(round2, 24, SILENT), 40).unwrap();
    w.probe(reply(open, 24, Reading::Alive), 41).unwrap();
    assert!(
        w.probes().next().is_none(),
        "an earlier-round ALIVE still vetoes"
    );
}

#[test]
fn replies_are_dated_by_their_issuance_and_floors_survive_eviction() {
    let mut w = suspect();
    let open = w.probes().next().unwrap();
    w.probe(reply(open, 21, SILENT), 30).unwrap();
    w.probe(reply(open, 22, SILENT), 30).unwrap();
    tick(&mut w, 40);
    let n = w.published().to_vec();
    for t in [50, 60, 70] {
        tick(&mut w, t);
    }
    assert!(!valid(&w, &n[0], 70), "the votes lapsed");
    let held = w.probes().next().unwrap();
    assert!(
        held.issued > open.issued,
        "each window issues a new request"
    );
    w.probe(reply(open, 21, SILENT), 70).unwrap();
    w.probe(reply(open, 22, SILENT), 70).unwrap();
    assert!(
        !valid(&w, &n[0], 70),
        "a delayed reply counts from its issuance and renews nothing"
    );
    w.probe(reply(held, 21, SILENT), 70).unwrap();
    w.probe(reply(held, 22, SILENT), 70).unwrap();
    assert!(valid(&w, &n[0], 70), "fresh issuances renew the quorum");
    let unissued = ProbeRequest {
        issued: held.issued + 1,
        ..held
    };
    let before = w.snapshot();
    assert_eq!(
        w.probe(reply(unissued, 24, SILENT), 70),
        Err(WatchRefusal::Stale),
        "an issuance after the suspect's last window close"
    );
    assert_eq!(w.snapshot(), before);

    let mut narrow = bounds();
    narrow.arbiter.hosts = 2;
    let mut w = watch_with(&[record(1, 11, 2)], narrow);
    for t in [10, 20, 30] {
        tick(&mut w, t);
    }
    let open = w.probes().next().unwrap();
    w.probe(reply(open, 27, SILENT), 30).unwrap();
    w.probe(reply(open, 26, SILENT), 30).unwrap();
    tick(&mut w, 40);
    let round2 = w.probes().next().unwrap();
    w.probe(reply(round2, 27, SILENT), 40).unwrap();
    w.probe(reply(round2, 26, SILENT), 40).unwrap();
    w.probe(reply(round2, 22, SILENT), 40).unwrap();
    let before = w.snapshot();
    assert_eq!(
        w.probe(reply(open, 27, SILENT), 40),
        Err(WatchRefusal::Stale),
        "the evicted prober's older issuance"
    );
    assert_eq!(w.snapshot(), before);
}

#[test]
fn a_lapsed_vote_frees_its_place_for_a_new_prober() {
    let mut narrow = bounds();
    narrow.arbiter.hosts = 2;
    narrow.arbiter.rounds = 1;
    let mut w = watch_with(&[record(1, 11, 2)], narrow);
    for t in [10, 20, 30] {
        tick(&mut w, t);
    }
    let open = w.probes().next().unwrap();
    w.probe(reply(open, 21, SILENT), 30).unwrap();
    w.probe(reply(open, 22, SILENT), 30).unwrap();
    tick(&mut w, 40);
    let n = w.published().to_vec();
    tick(&mut w, 50);
    tick(&mut w, 60);
    let held = w.probes().next().unwrap();
    w.probe(reply(held, 24, SILENT), 60).unwrap();
    w.probe(reply(held, 25, SILENT), 60).unwrap();
    assert!(valid(&w, &n[0], 60), "new probers took the lapsed places");
}

#[test]
fn an_unknown_reply_keeps_its_round_and_a_veto_outlasts_exhaustion() {
    let mut w = suspect();
    let open = w.probes().next().unwrap();
    w.probe(reply(open, 21, SILENT), 30).unwrap();
    tick(&mut w, 40);
    let round2 = w.probes().next().unwrap();
    w.probe(reply(round2, 21, Reading::Unknown), 40).unwrap();
    let before = w.snapshot();
    assert_eq!(
        w.probe(reply(open, 21, SILENT), 40),
        Err(WatchRefusal::Stale)
    );
    assert_eq!(w.snapshot(), before);

    let mut b = bounds();
    b.self_suspect = 2;
    let mut w = watch_with(&[record(1, 11, 2), record(2, 12, 2)], b);
    for t in [10, 20, 30] {
        tick(&mut w, t);
    }
    w.probe(reply(request_for(&w, 11), 24, Reading::Alive), 30)
        .unwrap();
    for t in [40, 50, 60] {
        tick(&mut w, t);
    }
    w.probe(reply(request_for(&w, 11), 21, Reading::Unknown), 60)
        .unwrap();
    let mut demands = Vec::new();
    for t in [70, 80, 90, 100, 110] {
        demands.push(tick(&mut w, t));
    }
    assert!(
        demands.iter().all(Option::is_none),
        "neither UNKNOWN nor exhaustion lifts the veto: {demands:?}"
    );
}

#[test]
fn sent_heartbeats_rise_and_older_retained_sends_still_date_reads() {
    let mut w = watch(&[record(1, 11, 2)]);
    w.sent(5, 100).unwrap();
    let before = w.snapshot();
    assert_eq!(w.sent(5, 200), Err(WatchRefusal::Stale));
    assert_eq!(w.sent(6, 99), Err(WatchRefusal::Time));
    assert_eq!(w.snapshot(), before);
    w.sent(6, 150).unwrap();
    w.heartbeat(&acking(11, 7, 1, 5, &[entry(1, Some(30))]), key, 160)
        .unwrap();
    assert_eq!(w.peer_read_at(), Some(70), "the older retained send");
    w.heartbeat(&acking(11, 7, 2, 6, &[entry(1, Some(200))]), key, 170)
        .unwrap();
    assert_eq!(w.peer_read_at(), Some(70), "an age above its send time");
    w.sent(7, 400).unwrap();
    w.heartbeat(&acking(11, 7, 3, 7, &[entry(1, Some(10))]), key, 300)
        .unwrap();
    assert_eq!(w.peer_read_at(), Some(70), "a send after the receipt");
    let other = sealed(
        &Header {
            ack: 6,
            ack_boot: [0x11; 16],
            ..header(11, 7, 4)
        },
        &[entry(1, Some(10))],
        OWN,
    );
    w.heartbeat(&other, key, 410).unwrap();
    assert_eq!(
        w.peer_read_at(),
        Some(70),
        "an acknowledgment of another observer boot"
    );
}

#[test]
fn a_dropped_prober_after_publication_withdraws_the_quorum() {
    let mut w = suspect();
    answer(&mut w, 30, SILENT);
    tick(&mut w, 40);
    let n = w.published().to_vec();
    assert!(valid(&w, &n[0], 40));
    let dropped: Vec<_> = placement()
        .into_iter()
        .filter(|(h, _)| *h != host(22))
        .collect();
    w.sync(&[record(1, 11, 2)], &dropped, 40).unwrap();
    assert!(!valid(&w, &n[0], 40));
}

#[test]
fn deadlines_from_reboot_and_tick_must_fit_the_dwell() {
    let mut long = bounds();
    long.arbiter.dwell = 1_000;
    let mut w = Watch::new(host(OWN), OBS_BOOT, long).unwrap();
    w.sync(&[record(1, 11, 2)], &placement(), 0).unwrap();
    w.heartbeat(&beat(11, 7, 1, &[]), key, 5).unwrap();
    let before = w.snapshot();
    let late = u64::MAX - 500;
    assert_eq!(
        w.heartbeat(&beat(11, 8, 1, &[]), key, late),
        Err(WatchRefusal::Time)
    );
    assert_eq!(w.tick(late, clock(late), true), Err(WatchRefusal::Time));
    assert_eq!(w.snapshot(), before);
}

#[test]
fn a_kept_nomination_revalidates_once_self_suspicion_ends() {
    let mut b = bounds();
    b.self_suspect = 2;
    let mut w = watch_with(&[record(1, 11, 2), record(2, 12, 2)], b);
    let mut kept = Vec::new();
    for (seq, t) in (1..=7).map(|n| (n, n * H)) {
        if t <= 40 {
            w.heartbeat(&beat(12, 7, seq, &[]), key, t - 5).unwrap();
        }
        let request = w.probes().find(|r| r.suspect == host(11));
        if let Some(r) = request {
            w.probe(reply(r, 21, SILENT), t - H).unwrap();
            w.probe(reply(r, 22, SILENT), t - H).unwrap();
        }
        tick(&mut w, t);
        kept.extend(w.published().iter().copied());
    }
    let n = kept[0];
    assert!(dead(&w, 12) && !valid(&w, &n, 70), "suspecting at 70");
    w.probe(reply(request_for(&w, 12), 24, Reading::Alive), 70)
        .unwrap();
    for t in [80, 90] {
        let r = request_for(&w, 11);
        w.probe(reply(r, 21, SILENT), t - H).unwrap();
        w.probe(reply(r, 22, SILENT), t - H).unwrap();
        tick(&mut w, t);
    }
    assert!(
        valid(&w, &n, 90),
        "the tick at the deadline clears self-suspicion"
    );
}

/// A full record whose votes all count refuses, as `Prober`, a DEAD reply to a request issued more than the vote
/// lifetime before `now`, although the reply's partition is uncovered and its observer class unrepresented. The
/// record keeps its counting votes, so the distinct counting partitions stay as many and the nomination published
/// in the cycle still revalidates.
#[test]
fn a_lapsed_dead_reply_of_a_new_class_takes_no_counting_votes_place() {
    let mut narrow = bounds();
    narrow.arbiter.hosts = 2;
    let mut w = watch_with(&[record(1, 11, 2)], narrow);
    for t in [10, 20, 30] {
        tick(&mut w, t);
    }
    assert!(dead(&w, 11));

    // Round one's request, issued at 30. Two probers of one observer class in two partitions fill the record.
    let first = w.probes().next().unwrap();
    w.probe(classed(first, 21, 1, SILENT), 30).unwrap();
    w.probe(classed(first, 22, 1, SILENT), 30).unwrap();
    tick(&mut w, 40);
    let published = w.published().to_vec();
    assert_eq!(published.len(), 1, "two partitions are a quorum");
    for t in [50, 60, 70] {
        tick(&mut w, t);
    }
    // The same probers renew their votes on the request issued at the last window close. A DEAD vote counts for
    // `h * rounds + jitter = 35` after its request's issuance.
    let held = w.probes().next().unwrap();
    assert!(held.issued + 35 >= 70 && first.issued + 35 < 70);
    w.probe(classed(held, 21, 1, SILENT), 70).unwrap();
    w.probe(classed(held, 22, 1, SILENT), 70).unwrap();
    assert!(
        valid(&w, &published[0], 70),
        "both places hold counting votes of two partitions"
    );

    // A third prober's DEAD reply to round one's request arrives at 70, after its vote stopped counting
    // (30 + 35 < 70). Its observer class is new and its partition uncovered, and every recorded vote counts.
    // In a counting vote's place it would lower the distinct counting partitions from two to one, so `probe`
    // refuses it.
    let before = w.snapshot();
    let late = w.probe(classed(first, 24, 2, SILENT), 70);
    assert!(
        valid(&w, &published[0], 70),
        "a DEAD reply that no longer counts took a counting vote's place and the quorum of two partitions fell to \
         one: probe returned {late:?}"
    );
    assert_eq!(late, Err(WatchRefusal::Prober));
    assert_eq!(
        w.snapshot(),
        before,
        "a refusal leaves the detector unchanged"
    );
}

/// A full record whose votes all count also refuses a lapsed DEAD reply from an uncovered partition when one
/// recorded partition is repeated. A reply that counts keeps its own observer class represented in the place it
/// takes; the lapsed reply would take the place of the only counting vote of its class, so the refusal keeps the
/// second class that a quorum of gray votes needs.
#[test]
fn a_lapsed_dead_reply_leaves_a_gray_quorum_its_second_class() {
    let mut narrow = bounds();
    narrow.arbiter.hosts = 3;
    let mut w = watch_with(&[record(1, 11, 2)], narrow);
    for t in [10, 20, 30] {
        tick(&mut w, t);
    }
    assert!(dead(&w, 11));

    // Three gray votes fill the record: partition 2 twice, in classes 2 and 1, and partition 3 in class 1.
    let votes = [(26, 2), (27, 1), (22, 1)];
    let first = w.probes().next().unwrap();
    for (prober, class) in votes {
        w.probe(classed(first, prober, class, GRAY), 30).unwrap();
    }
    tick(&mut w, 40);
    let published = w.published().to_vec();
    assert_eq!(
        published.len(),
        1,
        "two partitions and two classes are a gray quorum"
    );
    for t in [50, 60, 70] {
        tick(&mut w, t);
    }
    // The same probers renew their votes on the request issued at 70. A DEAD vote counts for 35 after its
    // request's issuance, so a vote on round one's request, issued at 30, has lapsed.
    let held = w.probes().next().unwrap();
    assert!(held.issued + 35 >= 70 && first.issued + 35 < 70);
    for (prober, class) in votes {
        w.probe(classed(held, prober, class, GRAY), 70).unwrap();
    }
    assert!(
        valid(&w, &published[0], 70),
        "every place holds a counting vote"
    );

    // Prober 24 answers round one's request at 70 in class 2, from partition 5, which no vote covers. Partition 2
    // is repeated, and prober 26's vote there is the only counting vote of class 2. In its place the lapsed reply
    // would leave class 1 alone among the counting votes.
    let before = w.snapshot();
    let late = w.probe(classed(first, 24, 2, GRAY), 70);
    assert!(
        valid(&w, &published[0], 70),
        "a DEAD reply that no longer counts took the place of the only counting vote of its class and the gray \
         quorum lost its second class: probe returned {late:?}"
    );
    assert_eq!(late, Err(WatchRefusal::Prober));
    assert_eq!(
        w.snapshot(),
        before,
        "a refusal leaves the detector unchanged"
    );
}

/// SELF-SUSPICION through the census: with the threshold at two, two of three tracked peers suspected at one tick
/// leave a self-suspicion deadline, so the census reports the dwell left at the last tick, the detector fields read
/// it as positive, and no nomination is published. With the threshold at three the same history suspects no self:
/// the dwell reads 0 and both targets publish. Reading the census changes no detector state.
#[test]
fn the_census_reports_self_suspicion_and_the_nominations_published() {
    let records = [record(1, 11, 2), record(2, 12, 2), record(3, 14, 2)];
    for (threshold, self_suspects) in [(2, true), (3, false)] {
        let mut b = bounds();
        b.self_suspect = threshold;
        let mut w = watch_with(&records, b);
        assert_eq!(
            w.census(),
            WatchCensus {
                tracked: 3,
                suspected: 0,
                suspect_left: None,
                nominations: 0,
            },
            "before the first tick"
        );
        let mut published = 0;
        let mut last = 0;
        for (seq, t) in (1..=5).map(|n| (n, n * H)) {
            w.heartbeat(&beat(14, 7, seq, &[entry(3, None)]), key, t - 5)
                .unwrap();
            answer(&mut w, t - H, SILENT);
            tick(&mut w, t);
            published += w.published().len() as u64;
            last = t;
        }
        let before = w.snapshot();
        let census = w.census();
        assert_eq!(w.snapshot(), before, "reading the census changes nothing");
        let left = if self_suspects { 20 } else { 0 };
        assert_eq!(
            census,
            WatchCensus {
                tracked: 3,
                suspected: 2,
                suspect_left: Some(left),
                nominations: published,
            },
            "threshold {threshold}"
        );
        assert_eq!(published, if self_suspects { 0 } else { 2 });
        tick(&mut w, last + H);
        assert!(w.published().is_empty(), "a later tick publishes nothing");
        if self_suspects {
            // Every peer beats again, so the suspicions clear and the dwell runs down to its deadline.
            let mut lefts = Vec::new();
            for (seq, t) in (6..=12).map(|n| (n, (n + 1) * H)) {
                for peer in [11, 12, 14] {
                    w.heartbeat(&beat(peer, 7, seq, &[]), key, t - 5).unwrap();
                }
                tick(&mut w, t);
                lefts.push(w.census().suspect_left.unwrap());
            }
            assert!(lefts.windows(2).all(|pair| pair[1] <= pair[0]), "{lefts:?}");
            assert!(
                lefts.iter().any(|&left| left > 0 && left < 20),
                "the dwell runs down: {lefts:?}"
            );
            assert_eq!(lefts.last(), Some(&0), "the dwell ended: {lefts:?}");
        }
        assert_eq!(
            w.census().nominations,
            published,
            "the count keeps the nominations of earlier ticks"
        );
        let detector = crate::failover::report::Detector::of(&census);
        assert_eq!(
            (
                detector.peers,
                detector.self_suspect_us,
                detector.nominations
            ),
            (
                crate::failover::report::Members::Known { used: 2, limit: 3 },
                Some(left),
                Some(published)
            )
        );
    }
}

pub(crate) const DECLARED: Reading = Reading::Dead(Failure::Declared);

/// A heartbeat from `sender` reporting itself unhealthy, with flat counters and no outstanding work.
fn held(sender: u64, sequence: u64) -> Vec<u8> {
    let header = Header {
        healthy: false,
        io: 0,
        completions: 0,
        pending: 0,
        ..header(sender, 7, sequence)
    };
    sealed(&header, &[], OWN)
}

/// A heartbeat from `sender` reporting itself healthy with outstanding work and flat counters, an observed stall.
fn stalled(sender: u64, sequence: u64) -> Vec<u8> {
    let header = Header {
        io: 0,
        completions: 0,
        ..header(sender, 7, sequence)
    };
    sealed(&header, &[], OWN)
}

/// Answers every open probe from probers 21 and 22, both of observer class 1, with `reading` of its suspect.
fn answer_one_class(w: &mut Watch, now: u64, reading: &dyn Fn(u64) -> Reading) {
    let requests: Vec<_> = w.probes().collect();
    for r in requests {
        for prober in [21, 22] {
            w.probe(classed(r, prober, 1, reading(r.suspect.get())), now)
                .unwrap();
        }
    }
}

/// The shards a run of `windows` windows publishes and its last repair demand: before each tick at `n * H` the
/// observer admits `beats(n)`, sent at `n * H - 5`, and the probers answer the last tick's probes with one class.
fn run_one_class(
    w: &mut Watch,
    windows: u64,
    beats: &dyn Fn(u64) -> Vec<Vec<u8>>,
    reading: &dyn Fn(u64) -> Reading,
) -> (Vec<u32>, Option<RepairDemand>) {
    let (mut shards, mut repair) = (Vec::new(), None);
    for n in 1..=windows {
        let t = n * H;
        for bytes in beats(n) {
            w.heartbeat(&bytes, key, t - 5).unwrap();
        }
        answer_one_class(w, t - H, reading);
        repair = tick(w, t).or(repair);
        shards.extend(w.published().iter().map(|n| n.shard.get()));
    }
    shards.sort_unstable();
    (shards, repair)
}

/// The run of [`two_held_hosts_and_a_silent_one_at_a_threshold_of_three_nominate_the_silent_one`]: owners 11 and 12
/// send `beats` and the probers read them `kind`; owner 14 is silent. Returns the published shards, the last repair
/// demand and the census's suspect count.
fn two_held_and_one_silent(
    beats: fn(u64, u64) -> Vec<u8>,
    kind: Reading,
) -> (Vec<u32>, Option<RepairDemand>, usize) {
    let records = [record(1, 11, 2), record(2, 12, 2), record(3, 14, 2)];
    let mut w = watch(&records);
    let reading = move |suspect: u64| if suspect == 14 { SILENT } else { kind };
    let both = move |n: u64| vec![beats(11, n), beats(12, n)];
    let (shards, repair) = run_one_class(&mut w, 5, &both, &reading);
    (shards, repair, w.census().suspected)
}

/// Two hosts that declare themselves held and one silent host, at the self-suspicion threshold of 3: the fresh
/// declarations count no suspect toward the threshold, so all three owners are nominated on DEAD votes of one
/// observer class, the silent one included. Observed stalls in their place, healthy heartbeats with flat counters,
/// still count toward the threshold: the observer suspects itself and nominates nothing.
#[test]
fn two_held_hosts_and_a_silent_one_at_a_threshold_of_three_nominate_the_silent_one() {
    let (shards, repair, suspected) = two_held_and_one_silent(held, DECLARED);
    assert_eq!(repair, None, "fresh declarations are no self-suspicion");
    assert_eq!(shards, [1, 2, 3], "the silent owner and both held owners");
    assert_eq!(suspected, 1, "only the silent host counts");

    let (shards, repair, _) = two_held_and_one_silent(stalled, GRAY);
    assert!(
        repair.is_some_and(|r| r.suspects == 3),
        "observed stalls count"
    );
    assert!(shards.is_empty(), "the stalled run nominates nothing");
}

/// The control that counts fresh declarations toward self-suspicion, and the one that reads them as observed
/// stalls, each fail the two-held case: the observer suspects itself and the silent owner is not nominated.
#[test]
fn the_controls_that_count_or_gray_declarations_fail_the_two_held_case() {
    for defect in ["declared-counts", "declared-as-gray"] {
        let (shards, repair, _) = planted(defect, || two_held_and_one_silent(held, DECLARED));
        assert!(repair.is_some(), "{defect}: the observer suspects itself");
        assert!(
            !shards.contains(&3),
            "{defect}: the control does not nominate the silent owner: {shards:?}"
        );
    }
}

/// The run of the brake case: owners 11, 12 and 23 send `beats`, which the probers read declared, and owner 14 is
/// silent. After the fifth window prober 24 adds a declared vote of a second class for owner 11. Returns the shards
/// published in the five windows, those of the sixth, the last repair demand and the census's suspect count.
fn three_declared_and_one_silent(
    beats: fn(u64) -> Vec<Vec<u8>>,
) -> (Vec<u32>, Vec<u32>, Option<RepairDemand>, usize) {
    let records = [
        record(1, 11, 2),
        record(2, 12, 2),
        record(3, 23, 2),
        record(4, 14, 2),
    ];
    let reading = |suspect: u64| if suspect == 14 { SILENT } else { DECLARED };
    let mut w = watch(&records);
    let (shards, repair) = run_one_class(&mut w, 5, &beats, &reading);
    let suspected = w.census().suspected;
    let open = request_for(&w, 11);
    w.probe(classed(open, 24, 2, DECLARED), 50).unwrap();
    for bytes in beats(6) {
        w.heartbeat(&bytes, key, 55).unwrap();
    }
    tick(&mut w, 60);
    let later = w.published().iter().map(|n| n.shard.get()).collect();
    (shards, later, repair, suspected)
}

/// Three fresh declarations at a threshold of 3 nominate none of their owners on one observer class, while the
/// silent owner beside them is nominated; a declared owner under the brake still nominates once a vote of a second
/// class corroborates, because the brake reads its evidence gray. Two declarations nominate both owners.
#[test]
fn three_fresh_declarations_brake_nominations_on_declared_evidence_and_a_silent_host_still_nominates()
 {
    let three = |n: u64| vec![held(11, n), held(12, n), held(23, n)];
    let (shards, later, repair, suspected) = three_declared_and_one_silent(three);
    assert_eq!(repair, None);
    assert_eq!(shards, [4], "only the silent owner");
    assert_eq!(suspected, 1);
    assert_eq!(later, [1], "a second class corroborates the braked owner");

    let two = |n: u64| vec![held(11, n), held(12, n), beat(23, 7, n, &[])];
    let (shards, _, repair, _) = three_declared_and_one_silent(two);
    assert_eq!(repair, None);
    assert_eq!(shards, [1, 2, 4], "two declarations nominate");
}

/// The control without the brake fails the brake case: three declarations of one class nominate every owner.
#[test]
fn the_control_without_the_brake_nominates_every_declared_owner() {
    let three = |n: u64| vec![held(11, n), held(12, n), held(23, n)];
    let (shards, ..) = planted("unbraked", || three_declared_and_one_silent(three));
    assert_eq!(
        shards,
        [1, 2, 3, 4],
        "the control nominates on correlated declarations"
    );
}

/// A run in which owner 11 declares itself held for four windows and is nominated on declared votes of one class,
/// then sends a healthy heartbeat at 42. Returns whether the nomination revalidates at 41 and at 43, and the
/// detector's reading of 11 at 43.
fn a_declaration_then_a_healthy_heartbeat() -> (bool, bool, Option<Liveness>) {
    let mut w = watch(&[record(1, 11, 2)]);
    let (shards, _) = run_one_class(&mut w, 4, &|n| vec![held(11, n)], &|_| DECLARED);
    assert_eq!(shards, [1]);
    let nominated = w.published()[0];
    let before = valid(&w, &nominated, 41);
    w.heartbeat(&beat(11, 7, 5, &[]), key, 42).unwrap();
    (before, valid(&w, &nominated, 43), w.liveness(host(11)))
}

/// A declared reading counts only until a heartbeat reporting the host healthy arrives: after one, the detector's
/// reading, which a prober answers with, is gray, revalidation of a nomination made on declared evidence refuses,
/// and the next window's declared votes of one class nominate nothing. A window with no heartbeat reads the
/// declared suspicion gray as well.
#[test]
fn a_declaration_that_aged_out_gives_no_declared_reading_and_no_nomination() {
    let (before, after, reading) = a_declaration_then_a_healthy_heartbeat();
    assert!(before, "still declaring");
    assert!(!after, "a healthy heartbeat ends the declaration");
    assert!(matches!(
        reading,
        Some(Liveness::Dead(Suspicion {
            failure: Failure::Gray,
            ..
        }))
    ));

    let declare = |n: u64| vec![held(11, n)];
    let mut w = watch(&[record(1, 11, 2)]);
    let (shards, _) = run_one_class(&mut w, 3, &declare, &|_| DECLARED);
    assert!(shards.is_empty());
    w.heartbeat(&beat(11, 7, 4, &[]), key, 35).unwrap();
    answer_one_class(&mut w, 30, &|_| DECLARED);
    tick(&mut w, 40);
    assert!(
        w.published().is_empty(),
        "declared votes of one class after a healthy heartbeat"
    );

    let mut w = watch(&[record(1, 11, 2)]);
    run_one_class(&mut w, 3, &declare, &|_| DECLARED);
    answer_one_class(&mut w, 30, &|_| DECLARED);
    tick(&mut w, 40);
    assert!(matches!(
        w.liveness(host(11)),
        Some(Liveness::Dead(Suspicion {
            failure: Failure::Gray,
            ..
        }))
    ));
    assert!(w.published().is_empty(), "a window with no heartbeat");
}

/// The control that keeps a declaration fresh across a healthy heartbeat fails the freshness case: the nomination
/// still revalidates and the reading stays declared.
#[test]
fn the_control_that_keeps_a_declaration_fresh_revalidates_after_a_healthy_heartbeat() {
    let (_, after, reading) = planted("stale-declared", a_declaration_then_a_healthy_heartbeat);
    assert!(after, "the control revalidates after the healthy heartbeat");
    assert!(matches!(
        reading,
        Some(Liveness::Dead(Suspicion {
            failure: Failure::Declared,
            ..
        }))
    ));
}

/// A declared vote counts for the vote lifetime after its request was issued, `h * rounds + jitter` = 35: a
/// nomination on declared votes issued at 30 revalidates at 65 and refuses at 66 once they lapse, though the host
/// still declares.
#[test]
fn a_declared_vote_past_its_lifetime_gives_no_vote() {
    let reading = |_: u64| DECLARED;
    let mut w = watch(&[record(1, 11, 2)]);
    let (shards, _) = run_one_class(&mut w, 4, &|n| vec![held(11, n)], &reading);
    assert_eq!(shards, [1]);
    let kept = w.published()[0];
    for (n, t) in [(5, 50), (6, 60)] {
        w.heartbeat(&held(11, n), key, t - 5).unwrap();
        tick(&mut w, t);
    }
    assert!(valid(&w, &kept, 65), "the votes count through 65");
    assert!(!valid(&w, &kept, 66), "the votes lapsed");
}

thread_local! {
    static PLANTS: std::cell::RefCell<Vec<&'static str>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// The defects a control plants in the detector and arbiter cores, by name: `declared-as-gray` reads `D` declared
/// windows as an observed stall, `declared-counts` counts fresh declarations toward self-suspicion, `unbraked`
/// removes the brake on correlated declarations, `stale-declared` keeps a declared reading fresh across a healthy
/// heartbeat, `gray-unread-after-quorum` reads no vote past the quorum's `k`-th counted one for gray evidence, and
/// `stale-gray-counts` reads gray evidence from votes that do not count.
const DEFECTS: [&str; 7] = [
    "declared-as-gray",
    "declared-counts",
    "unbraked",
    "stale-declared",
    "gray-unread-after-quorum",
    "stale-gray-counts",
    "recovering-counts",
];

/// Whether the running control planted `defect`.
pub(crate) fn plant(defect: &str) -> bool {
    PLANTS.with(|plants| plants.borrow().contains(&defect))
}

/// Runs `body` with `defect` planted on this thread.
pub(crate) fn planted<R>(defect: &'static str, body: impl FnOnce() -> R) -> R {
    assert!(DEFECTS.contains(&defect), "no defect {defect}");
    PLANTS.with(|plants| plants.borrow_mut().push(defect));
    let result = body();
    PLANTS.with(|plants| plants.borrow_mut().retain(|d| *d != defect));
    result
}

/// Three fresh declarations at a threshold of 3 stay out of the self-suspicion count, so the observer raises no
/// repair demand; one window with no heartbeat ages every declaration to gray, and the same three suspects then
/// put the observer in self-suspicion at that close.
#[test]
fn declarations_that_age_out_count_toward_self_suspicion_again() {
    let records = [record(1, 11, 2), record(2, 12, 2), record(3, 23, 2)];
    let mut w = watch(&records);
    let three = |n: u64| vec![held(11, n), held(12, n), held(23, n)];
    let (_, repair) = run_one_class(&mut w, 3, &three, &|_| SILENT);
    assert_eq!(repair, None, "fresh declarations");
    assert_eq!(w.census().suspected, 0);
    assert_eq!(
        tick(&mut w, 40),
        Some(RepairDemand {
            suspects: 3,
            until: 60
        }),
        "aged declarations count"
    );
}

/// One tick of a [`recovering`] run: its repair demand, the census's suspect count, the shards it published and
/// owner 11's reading.
type Recovered = (Option<RepairDemand>, usize, Vec<u32>, Option<Liveness>);

/// The run of the recovering-declaration cases. Owners 11, 12 and 23 declare for three windows and owner 14 is
/// silent throughout. In each window from the fourth the three send `after(owner, window)`, or nothing where it
/// returns `None`, and the probers of one class read every suspect silent. Returns the ticks at `4 * H` to `9 * H`.
fn recovering(after: &dyn Fn(u64, u64) -> Option<Vec<u8>>) -> Vec<Recovered> {
    let records = [
        record(1, 11, 2),
        record(2, 12, 2),
        record(3, 23, 2),
        record(4, 14, 2),
    ];
    let mut w = watch(&records);
    let three = |n: u64| vec![held(11, n), held(12, n), held(23, n)];
    let (shards, repair) = run_one_class(&mut w, 3, &three, &|_| SILENT);
    assert_eq!((shards, repair), (vec![], None), "the hold");
    assert_eq!(w.census().suspected, 1, "the silent owner");
    (4..=9)
        .map(|n| {
            let t = n * H;
            for owner in [11, 12, 23] {
                if let Some(bytes) = after(owner, n) {
                    w.heartbeat(&bytes, key, t - 5).unwrap();
                }
            }
            answer_one_class(&mut w, t - H, &|_| SILENT);
            let repair = tick(&mut w, t);
            let shards = w.published().iter().map(|n| n.shard.get()).collect();
            (repair, w.census().suspected, shards, w.liveness(host(11)))
        })
        .collect()
}

/// A healthy heartbeat with no outstanding work, which counts as progress.
fn healthy(owner: u64, n: u64) -> Option<Vec<u8>> {
    Some(beat(owner, 7, n, &[]))
}

/// Three hosts that leave a declared hold together, at a threshold of 3: each healthy, progressing heartbeat turns
/// its owner's declared suspicion gray, the gray exit ends it two windows and the dwell later, and none of the three
/// counts toward self-suspicion on the way. The observer raises no repair demand and nominates the silent owner
/// beside them at the first tick after the brake ends.
#[test]
fn hosts_that_leave_a_hold_together_progressing_raise_no_repair_demand() {
    let ticks = recovering(&healthy);
    let gray = |since: u64| {
        Some(Liveness::Dead(Suspicion {
            generation: ObservationGeneration(1),
            failure: Failure::Gray,
            since,
        }))
    };
    for (n, (repair, suspected, _, _)) in (4..).zip(&ticks) {
        assert_eq!(*repair, None, "window {n}");
        assert_eq!(*suspected, 1, "window {n}: only the silent owner counts");
    }
    assert_eq!(
        ticks[0].3,
        gray(30),
        "the suspicion turns gray and keeps its stamp"
    );
    assert_eq!(ticks[1].3, gray(30));
    assert_eq!(ticks[2].3, Some(Liveness::Alive), "the gray exit");
    assert_eq!(ticks[0].2, [4], "the silent owner");
}

/// The control that counts a recovering declaration fails that case: the observer suspects itself at the first
/// healthy window, renews the demand until the gray exit and publishes nothing while it lasts.
#[test]
fn the_control_that_counts_recovering_declarations_raises_a_repair_demand() {
    let ticks = planted("recovering-counts", || recovering(&healthy));
    assert_eq!(
        ticks[0].0,
        Some(RepairDemand {
            suspects: 4,
            until: 60
        }),
        "the control raises a repair demand"
    );
    assert_eq!(
        ticks[1].0,
        Some(RepairDemand {
            suspects: 4,
            until: 70
        })
    );
    assert!(
        ticks[..3].iter().all(|(_, _, shards, _)| shards.is_empty()),
        "the control publishes nothing under the demand"
    );
}

/// The exemption needs progress in every observed window: a host that leaves its hold with outstanding work and
/// flat counters is an observed stall, a recovering host that then stalls or misses a window counts again, and an
/// unobserved close counts every recovering host until its next progressing window.
#[test]
fn a_recovering_declaration_counts_again_without_progress() {
    let demand = |until: u64| Some(RepairDemand { suspects: 4, until });
    let flat = recovering(&|owner, n| Some(stalled(owner, n)));
    assert_eq!(
        flat[0].0,
        demand(60),
        "healthy heartbeats with flat counters"
    );

    let then_stalled = recovering(&|owner, n| match n {
        4 => healthy(owner, n),
        _ => Some(stalled(owner, n)),
    });
    assert_eq!(then_stalled[0].0, None);
    assert_eq!(
        then_stalled[1].0,
        demand(70),
        "a stall after one progressing window"
    );

    let then_absent = recovering(&|owner, n| if n == 4 { healthy(owner, n) } else { None });
    assert_eq!(then_absent[0].0, None);
    assert_eq!(then_absent[1].0, demand(70), "a window with no heartbeat");
}

/// An unobserved close resets the gray exit count, so every recovering host counts at that tick.
#[test]
fn an_observer_pause_counts_recovering_declarations() {
    let records = [record(1, 11, 2), record(2, 12, 2), record(3, 23, 2)];
    let mut w = watch(&records);
    let three = |n: u64| vec![held(11, n), held(12, n), held(23, n)];
    assert_eq!(run_one_class(&mut w, 3, &three, &|_| SILENT).1, None);
    for owner in [11, 12, 23] {
        w.heartbeat(&beat(owner, 7, 4, &[]), key, 35).unwrap();
    }
    assert_eq!(tick(&mut w, 40), None, "one progressing window");
    assert_eq!(w.census().suspected, 0);
    // The tick comes more than a window and the jitter after the last one, so the close is unobserved.
    assert_eq!(
        tick(&mut w, 66),
        Some(RepairDemand {
            suspects: 3,
            until: 86
        })
    );
}

/// The exemption holds between a healthy, progressing heartbeat and the window close that turns the declared
/// suspicion gray: a census read and a tick that closes no window count no recovering host. A healthy heartbeat with
/// flat counters and outstanding work in the open window counts its sender.
#[test]
fn a_healthy_progressing_heartbeat_exempts_its_sender_before_the_window_closes() {
    let run = |beats: fn(u64, u64) -> Vec<u8>| {
        let records = [record(1, 11, 2), record(2, 12, 2), record(3, 23, 2)];
        let mut w = watch(&records);
        let three = |n: u64| vec![held(11, n), held(12, n), held(23, n)];
        assert_eq!(run_one_class(&mut w, 3, &three, &|_| SILENT).1, None);
        for owner in [11, 12, 23] {
            w.heartbeat(&beats(owner, 4), key, 35).unwrap();
        }
        (w.census().suspected, tick(&mut w, 36))
    };
    assert_eq!(run(|owner, n| beat(owner, 7, n, &[])), (0, None));
    assert_eq!(
        run(stalled),
        (
            3,
            Some(RepairDemand {
                suspects: 3,
                until: 56
            })
        )
    );
}

/// The brake reads declared votes gray as well as a declared local suspicion: under the brake a silent owner with
/// declared votes of one class is not published, and neither is a declared owner with silent votes of one class.
/// The control below the brake, two declarations, publishes both.
#[test]
fn the_brake_reads_declared_votes_and_a_declared_suspicion_gray() {
    let records = [
        record(1, 11, 2),
        record(2, 12, 2),
        record(3, 23, 2),
        record(4, 14, 2),
    ];
    let reversed = |suspect: u64| if suspect == 14 { DECLARED } else { SILENT };
    let mut w = watch(&records);
    let three = |n: u64| vec![held(11, n), held(12, n), held(23, n)];
    let (shards, repair) = run_one_class(&mut w, 5, &three, &reversed);
    assert_eq!(repair, None);
    assert!(shards.is_empty(), "under the brake: {shards:?}");

    let mut w = watch(&records);
    let two = |n: u64| vec![held(11, n), held(12, n), beat(23, 7, n, &[])];
    let (shards, _) = run_one_class(&mut w, 5, &two, &reversed);
    assert_eq!(shards, [1, 2, 4], "below the brake");
}

/// Revalidation applies the brake at its own time: a nomination published while two owners declare revalidates
/// until a third owner's declaration turns fresh, and refuses after it.
#[test]
fn revalidation_refuses_a_declared_nomination_once_the_brake_holds() {
    let records = [record(1, 11, 2), record(2, 12, 2), record(3, 23, 2)];
    let mut w = watch(&records);
    // Owner 23 is healthy for three windows, then declares from its fourth.
    let late = |n: u64| {
        let third = if n <= 3 {
            beat(23, 7, n, &[])
        } else {
            held(23, n)
        };
        vec![held(11, n), held(12, n), third]
    };
    let (shards, _) = run_one_class(&mut w, 4, &late, &|_| DECLARED);
    assert_eq!(shards, [1, 2]);
    let kept = *w.published().iter().find(|n| n.shard.get() == 1).unwrap();
    assert!(valid(&w, &kept, 41), "two fresh declarations");
    for n in 5..=6 {
        let t = n * H;
        for bytes in late(n) {
            w.heartbeat(&bytes, key, t - 5).unwrap();
        }
        answer_one_class(&mut w, t - H, &|_| DECLARED);
        tick(&mut w, t);
    }
    for h in [11, 12, 23] {
        assert!(
            matches!(w.liveness(host(h)), Some(Liveness::Dead(s)) if s.failure == Failure::Declared),
            "{h} declares"
        );
    }
    assert!(!valid(&w, &kept, 61), "the brake holds at revalidation");
}

/// An owner's declaration still counts toward the brake in a window its heartbeat misses, so the other declared
/// owners' shards stay unpublished on one observer class. The brake releases and the watch publishes shards 1 and
/// 2 when owner 23 sends a healthy heartbeat or reads silent after `D` consecutive windows without a heartbeat.
#[test]
fn the_brake_holds_through_a_declared_owners_empty_window_and_ends_at_its_healthy_heartbeat_or_silence()
 {
    let records = [
        record(1, 11, 2),
        record(2, 12, 2),
        record(3, 23, 2),
        record(4, 14, 2),
    ];
    let reading = |suspect: u64| if suspect == 14 { SILENT } else { DECLARED };
    let run = |windows: u64, third: &dyn Fn(u64) -> Option<Vec<u8>>| {
        let mut w = watch(&records);
        let beats = |n: u64| {
            let mut beats = vec![held(11, n), held(12, n)];
            beats.extend(third(n));
            beats
        };
        let (shards, repair) = run_one_class(&mut w, windows, &beats, &reading);
        assert_eq!(repair, None);
        shards
    };

    let skips = |n: u64| (n != 4).then(|| held(23, n));
    assert_eq!(
        run(5, &skips),
        [4],
        "a window with no heartbeat keeps the brake"
    );

    let recovers = |n: u64| {
        Some(if n < 4 {
            held(23, n)
        } else {
            beat(23, 7, n, &[])
        })
    };
    assert_eq!(
        run(5, &recovers),
        [1, 2, 4],
        "a healthy heartbeat ends the declaration"
    );

    let stops = |n: u64| (n < 4).then(|| held(23, n));
    assert_eq!(
        run(5, &stops),
        [4],
        "two windows with no heartbeat keep the brake"
    );
    let published = run(6, &stops);
    assert!(
        published.contains(&1) && published.contains(&2),
        "the third reads silent and ends the declaration: {published:?}"
    );
}

/// A probe cycle that spends every round on UNKNOWN answers reads UNKNOWN at its judging close, and the declaration
/// under it stays fresh: three declaring owners at a threshold of 3 stay out of the self-suspicion count and keep
/// the brake through every spent cycle.
#[test]
fn an_exhausted_probe_cycle_keeps_a_fresh_declaration_out_of_self_suspicion() {
    let records = [record(1, 11, 2), record(2, 12, 2), record(3, 23, 2)];
    let mut w = watch(&records);
    let three = |n: u64| vec![held(11, n), held(12, n), held(23, n)];
    let mut unknown = false;
    for n in 1..=9 {
        let t = n * H;
        for bytes in three(n) {
            w.heartbeat(&bytes, key, t - 5).unwrap();
        }
        answer_one_class(&mut w, t - H, &|_| Reading::Unknown);
        assert_eq!(tick(&mut w, t), None, "{t}: no self-suspicion");
        unknown |= w.liveness(host(11)) == Some(Liveness::Unknown);
        assert_eq!(w.census().suspected, 0, "{t}");
    }
    assert!(unknown, "a spent cycle read UNKNOWN");
}
