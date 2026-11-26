use std::cell::Cell;

use super::{
    INBOX, Inbound, Link, LinkError, Message, NOMINATE_LEN, PEER_LEN, REQUEST_MAX, Request,
    STATUS_LEN, Status, VERSION, decode, encode, encode_status,
};
use crate::failover::detect::host::Revalidated;
use crate::failover::records::{Host, VolumeId};
use crate::failover::report::tests::bare;
use crate::failover::report::{Ended, Phase, RecordedRole};
use crate::failover::retire::Target;
use crate::host::Exit;
use crate::net::ownership::{ActivatedEpoch, Shard, ShardGeneration};

thread_local! {
    static TRAILING: Cell<bool> = const { Cell::new(false) };
}

pub(super) fn trailing() -> bool {
    TRAILING.with(Cell::get)
}

const PHASES: [Phase; 8] = [
    Phase::Starting,
    Phase::Recovering,
    Phase::Held,
    Phase::Standby,
    Phase::Serving,
    Phase::Withdrawn,
    Phase::Closing,
    Phase::Parked,
];

/// The largest shard generation.
const G_MAX: u64 = u32::MAX as u64;

/// The offset of a status's tenure generation, after the fixed header fields and the volume field.
const TENURE_AT: usize = 14 + crate::failover::records::VOLUME;

fn volume() -> VolumeId {
    VolumeId::new("vol-0123456789abcdef0").unwrap()
}

fn target(g: u64, owner: u64, attempts: u32) -> Target {
    Target {
        generation: ShardGeneration::new(g).unwrap(),
        owner: Host::new(owner).unwrap(),
        attempts,
    }
}

fn full(phase: Phase, ended: Option<Ended>) -> Status {
    Status {
        tenure: Some((
            ShardGeneration::new(G_MAX).unwrap(),
            ActivatedEpoch::new(ActivatedEpoch::MAX).unwrap(),
        )),
        target: Some(target(G_MAX, u64::MAX, u32::MAX)),
        report_age_us: Some(u64::MAX),
        read_age_us: Some(u64::MAX),
        io: u64::MAX,
        completions: u64::MAX,
        pending: u64::MAX,
        entry: Some(bare("vol-0b", RecordedRole::Owner)),
        ended,
        ..Status::idle(Shard::new(u32::MAX).unwrap(), volume(), u32::MAX, phase)
    }
}

fn messages() -> Vec<Inbound> {
    let witness = |shard: u32, until_us: u64, target: Target| {
        Inbound::Nominate(Revalidated {
            shard: Shard::new(shard).unwrap(),
            target,
            until_us,
        })
    };
    vec![
        witness(1, 0, target(1, 1, 0)),
        witness(u32::MAX, u64::MAX, target(G_MAX, u64::MAX, u32::MAX)),
        Inbound::Peer { read_at: None },
        Inbound::Peer { read_at: Some(0) },
        Inbound::Peer {
            read_at: Some(u64::MAX),
        },
        Inbound::Request(Request::new(&[7]).unwrap()),
        Inbound::Request(Request::new(&[0xa5; REQUEST_MAX]).unwrap()),
    ]
}

fn encoded(message: &Message) -> Vec<u8> {
    let mut out = vec![0; STATUS_LEN];
    let len = match message {
        Message::Status(status) => encode_status(status, &mut out),
        Message::Inbound(inbound) => encode(inbound, &mut out),
    }
    .unwrap();
    out.truncate(len);
    out
}

fn every_message() -> Vec<Message> {
    let shard = Shard::new(1).unwrap();
    let mut all = Vec::new();
    for (i, phase) in PHASES.into_iter().enumerate() {
        let idle = Status::idle(shard, VolumeId::new("vol-0").unwrap(), 0, phase);
        all.push(Message::Status(Box::new(idle)));
        let ended = [Ended::Stopped, Ended::Fault][i % 2];
        all.push(Message::Status(Box::new(full(phase, Some(ended)))));
    }
    all.extend(messages().into_iter().map(Message::Inbound));
    all
}

fn codec_rows() -> Result<(), String> {
    for message in every_message() {
        let bytes = encoded(&message);
        if decode(&bytes).as_ref() != Ok(&message) {
            return Err(format!("round trip of {message:?}"));
        }
        if encoded(&decode(&bytes).unwrap()) != bytes {
            return Err(format!("re-encoding of {message:?}"));
        }
        if decode(&bytes[..bytes.len() - 1]) != Err(LinkError::Length) {
            return Err(format!("one byte short of {message:?}"));
        }
        let mut long = bytes.clone();
        long.push(0);
        if decode(&long) != Err(LinkError::Length) {
            return Err(format!("one byte long of {message:?}"));
        }
        let mut version = bytes.clone();
        version[..2].copy_from_slice(&(VERSION + 1).to_be_bytes());
        if decode(&version) != Err(LinkError::Version) {
            return Err(format!("wrong version of {message:?}"));
        }
    }
    Ok(())
}

#[test]
fn every_message_round_trips_at_its_bounds_and_refuses_short_long_and_wrong_version() {
    assert_eq!(codec_rows(), Ok(()));
    let lens = [NOMINATE_LEN, PEER_LEN, 5 + 1, 5 + REQUEST_MAX];
    let inbound: Vec<_> = messages()
        .iter()
        .map(|m| encoded(&Message::Inbound(*m)).len())
        .collect();
    assert_eq!(
        inbound,
        [
            lens[0], lens[0], lens[1], lens[1], lens[1], lens[2], lens[3]
        ]
    );
}

#[test]
fn the_control_that_ignores_trailing_bytes_fails_the_one_byte_long_row() {
    TRAILING.with(|plant| plant.set(true));
    let rows = codec_rows();
    TRAILING.with(|plant| plant.set(false));
    assert!(
        rows.as_ref()
            .is_err_and(|row| row.starts_with("one byte long")),
        "{rows:?}"
    );
}

#[test]
fn unknown_labels_and_bytes_outside_their_encoding_refuse() {
    let status = encoded(&Message::Status(Box::new(full(Phase::Serving, None))));
    let idle = encoded(&Message::Status(Box::new(Status::idle(
        Shard::new(1).unwrap(),
        volume(),
        1,
        Phase::Parked,
    ))));
    let with = |bytes: &[u8], at: usize, value: u8| {
        let mut bytes = bytes.to_vec();
        bytes[at] = value;
        decode(&bytes)
    };
    assert_eq!(with(&status, 2, 5), Err(LinkError::Kind));
    assert_eq!(with(&status, 2, 0), Err(LinkError::Kind));
    assert_eq!(with(&status, 3, 0), Err(LinkError::Field), "phase 0");
    assert_eq!(with(&status, 3, 9), Err(LinkError::Field), "phase 9");
    assert_eq!(with(&status, 5, 9), Err(LinkError::Field), "exit 9");
    assert_eq!(with(&status, 4, 0xff), Err(LinkError::Field), "presence");
    let mut zero_shard = status.clone();
    zero_shard[6..10].fill(0);
    assert_eq!(decode(&zero_shard), Err(LinkError::Field), "zero shard");
    assert_eq!(
        with(&idle, TENURE_AT + 11, 2),
        Err(LinkError::Field),
        "absent tenure"
    );
    assert_eq!(
        with(&idle, STATUS_LEN - 1, 1),
        Err(LinkError::Field),
        "absent entry"
    );
    let mut high = status.clone();
    high[TENURE_AT..TENURE_AT + 8].copy_from_slice(&(G_MAX + 1).to_be_bytes());
    assert_eq!(
        decode(&high),
        Err(LinkError::Field),
        "generation above its bound"
    );
    let mut odd = status.clone();
    odd[TENURE_AT + 8..TENURE_AT + 12].copy_from_slice(&3u32.to_be_bytes());
    assert_eq!(decode(&odd), Err(LinkError::Field), "odd epoch");
    let mut entry = status.clone();
    entry[STATUS_LEN - 1] ^= 0xff;
    assert!(
        matches!(decode(&entry), Err(LinkError::Entry(_))),
        "{:?}",
        decode(&entry)
    );
    let peer = encoded(&Message::Inbound(Inbound::Peer { read_at: None }));
    assert_eq!(with(&peer, 3, 2), Err(LinkError::Field), "peer presence");
    assert_eq!(
        with(&peer, PEER_LEN - 1, 1),
        Err(LinkError::Field),
        "absent read time"
    );
    let mut nominate = encoded(&Message::Inbound(messages()[0]));
    nominate[3..7].fill(0);
    assert_eq!(decode(&nominate), Err(LinkError::Field), "zero shard");
    let mut request = encoded(&Message::Inbound(messages()[5]));
    request[3..5].copy_from_slice(&0u16.to_be_bytes());
    assert_eq!(decode(&request[..5]), Err(LinkError::Field), "no bytes");
    request[3..5].copy_from_slice(&(REQUEST_MAX as u16 + 1).to_be_bytes());
    assert_eq!(decode(&request), Err(LinkError::Field), "count above bound");
    assert_eq!(decode(&request[..4]), Err(LinkError::Length));
    assert_eq!(decode(&[0, 1]), Err(LinkError::Length));
    assert_eq!(Request::new(&[]), None);
    assert_eq!(Request::new(&[0; REQUEST_MAX + 1]), None);
}

#[test]
fn each_phase_and_exit_label_takes_its_table_place() {
    for (i, phase) in PHASES.into_iter().enumerate() {
        let bytes = encoded(&Message::Status(Box::new(Status::idle(
            Shard::new(1).unwrap(),
            volume(),
            1,
            phase,
        ))));
        assert_eq!(usize::from(bytes[3]), i + 1, "{phase:?}");
    }
    let exits = [
        (Exit::Stopped, Ended::Stopped),
        (Exit::Rerun(crate::host::Rerun::Records), Ended::Rerun),
        (
            Exit::Held {
                recovery: target(1, 1, 1),
            },
            Ended::Held,
        ),
        (Exit::Deposed, Ended::Deposed),
        (Exit::Retire(target(1, 1, 1)), Ended::Retire),
        (
            Exit::Refused(crate::host::Refusal::Restart(
                crate::failover::restart::Check::Unheld,
            )),
            Ended::Refused,
        ),
        (Exit::Retired, Ended::Retired),
        (Exit::Fault(String::new()), Ended::Fault),
    ];
    let idle = Status::idle(Shard::new(1).unwrap(), volume(), 1, Phase::Serving);
    for (i, (exit, label)) in exits.iter().enumerate() {
        assert_eq!(Ended::from(exit), *label);
        let parked = Message::Status(Box::new(idle.parked(exit)));
        let bytes = encoded(&parked);
        assert_eq!(bytes[5], i as u8 + 1);
        assert_eq!(decode(&bytes), Ok(parked), "{label:?} decodes to itself");
    }
}

#[test]
fn a_parked_status_keeps_the_last_entry_with_its_flip_flag_and_the_exit_label() {
    let mut last = full(Phase::Serving, None);
    last.entry = last
        .entry
        .map(|entry| crate::failover::report::VolumeEntry {
            flip: true,
            serving: Some(crate::failover::serving::State::Withdrawn),
            ..entry
        });
    let exit = Exit::Retire(target(3, 4, 5));
    let parked = last.parked(&exit);
    assert_eq!(parked.phase, Phase::Parked);
    assert_eq!((parked.entry, parked.target), (last.entry, last.target));
    assert_eq!(parked.ended, Some(Ended::Retire));
    assert_eq!(parked.tenure, None);
    let bytes = encoded(&Message::Status(Box::new(parked)));
    let Ok(Message::Status(decoded)) = decode(&bytes) else {
        panic!("the parked status decodes");
    };
    assert!(decoded.entry.is_some_and(|entry| entry.flip));
    assert_eq!(*decoded, parked);
}

#[test]
fn a_held_status_cell_refuses_the_publication_and_a_later_one_writes() {
    let link = Link::default();
    let first = Status::idle(Shard::new(1).unwrap(), volume(), 1, Phase::Serving);
    let second = Status { io: 9, ..first };
    assert!(link.status.publish(first));
    {
        let _held = link.status.hold();
        assert!(!link.status.publish(second));
    }
    assert_eq!(link.status.take(), Some(first));
    assert_eq!(link.status.take(), None);
    assert!(link.status.publish(second));
    assert_eq!(link.status.take(), Some(second));
}

#[test]
fn the_inbox_holds_its_bound_and_drains_in_order() {
    let link = Link::default();
    let peers: Vec<_> = (0..INBOX as u64)
        .map(|at| Inbound::Peer { read_at: Some(at) })
        .collect();
    for peer in &peers {
        assert!(link.inbox.deliver(*peer));
    }
    let extra = Inbound::Peer { read_at: None };
    assert!(!link.inbox.deliver(extra));
    let mut drained = Vec::new();
    link.inbox.drain(|message| drained.push(message));
    assert_eq!(drained, peers);
    let [first, second] = [messages()[0], messages()[1]];
    for message in [first, messages()[2], second] {
        assert!(link.inbox.deliver(message));
    }
    let Inbound::Nominate(latest) = second else {
        unreachable!()
    };
    assert_eq!(link.inbox.nomination(), Some(latest));
    assert_eq!(link.inbox.nomination(), None);
}

#[test]
fn a_nomination_replaces_the_queued_one_so_a_full_inbox_takes_the_newest() {
    let link = Link::default();
    let [older, newer] = [messages()[0], messages()[1]];
    assert!(link.inbox.deliver(older));
    let peers: Vec<_> = (1..INBOX as u64)
        .map(|at| Inbound::Peer { read_at: Some(at) })
        .collect();
    for peer in &peers {
        assert!(link.inbox.deliver(*peer));
    }
    assert!(
        !link.inbox.deliver(Inbound::Peer { read_at: None }),
        "the inbox is full"
    );
    assert!(
        link.inbox.deliver(newer),
        "the newer nomination replaces the queued one"
    );
    let mut drained = Vec::new();
    link.inbox.drain(|message| drained.push(message));
    let mut expected = peers;
    expected.push(newer);
    assert_eq!(drained, expected);
}

/// The longest a concurrent test waits for its other thread before it reports what arrived.
const PATIENCE: std::time::Duration = std::time::Duration::from_secs(120);

/// One thread delivers numbered messages and retries each refusal while another drains. Under that contention
/// the drain passes every message once, in delivery order, and a last drain after the deliverer ends finds the
/// inbox empty. The run samples the schedules the host produces; it explores no chosen interleaving.
#[test]
fn a_concurrent_drain_takes_every_delivered_message_in_order() {
    const COUNT: u64 = 20_000;
    let link = Link::default();
    let deadline = std::time::Instant::now() + PATIENCE;
    let late = || std::time::Instant::now() >= deadline;
    let mut drained = Vec::with_capacity(COUNT as usize);
    std::thread::scope(|scope| {
        let deliverer = scope.spawn(|| {
            for at in 0..COUNT {
                while !link.inbox.deliver(Inbound::Peer { read_at: Some(at) }) {
                    if late() {
                        return;
                    }
                    std::thread::yield_now();
                }
            }
        });
        while drained.len() < COUNT as usize && !(deliverer.is_finished() || late()) {
            link.inbox.drain(|message| drained.push(message));
        }
    });
    link.inbox.drain(|message| drained.push(message));
    assert_eq!(drained.len(), COUNT as usize, "messages drained");
    let expected: Vec<_> = (0..COUNT)
        .map(|at| Inbound::Peer { read_at: Some(at) })
        .collect();
    assert_eq!(drained, expected);
    link.inbox.drain(|_| panic!("the inbox is empty"));
}

/// While the other side holds the lock, a take and a drain return nothing and leave the status and the messages
/// with their flags set, so the next call takes them; that call clears the flag.
#[test]
fn a_take_or_drain_refused_by_a_held_lock_leaves_the_value_for_the_next_call() {
    use std::sync::atomic::Ordering::Relaxed;
    let link = Link::default();
    let status = Status::idle(Shard::new(1).unwrap(), volume(), 1, Phase::Serving);
    assert!(link.status.publish(status));
    {
        let held = link.status.hold();
        assert_eq!(link.status.take(), None);
        assert_eq!(*held, Some(status));
    }
    assert!(link.status.full.load(Relaxed));
    assert_eq!(link.status.take(), Some(status));
    assert!(!link.status.full.load(Relaxed));
    let peers: Vec<_> = (0..2)
        .map(|at| Inbound::Peer { read_at: Some(at) })
        .collect();
    for peer in &peers {
        assert!(link.inbox.deliver(*peer));
    }
    {
        let held = link.inbox.hold();
        link.inbox
            .drain(|_| panic!("the link side holds the inbox"));
        assert_eq!(held.len(), 2);
    }
    assert!(link.inbox.waiting.load(Relaxed));
    let mut drained = Vec::new();
    link.inbox.drain(|message| drained.push(message));
    assert_eq!(drained, peers);
    assert!(!link.inbox.waiting.load(Relaxed));
}

/// A drain whose callback unwinds leaves the messages after the one it took for the next drain.
#[test]
fn a_drain_that_unwinds_leaves_the_later_messages_queued() {
    let link = Link::default();
    let peers: Vec<_> = (0..3)
        .map(|at| Inbound::Peer { read_at: Some(at) })
        .collect();
    for peer in &peers {
        assert!(link.inbox.deliver(*peer));
    }
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        link.inbox
            .drain(|_| panic!("the callback unwinds on the first message"));
    }));
    assert!(unwound.is_err());
    let mut drained = Vec::new();
    link.inbox.drain(|message| drained.push(message));
    assert_eq!(drained, peers[1..]);
}

/// One thread publishes statuses with a rising count while another takes. Every taken status is newer than the
/// one before it, and the take after the publisher ends returns the last status when no earlier take did. The
/// run samples the schedules the host produces; it explores no chosen interleaving.
#[test]
fn a_concurrent_take_sees_rising_statuses_and_the_last_one() {
    const COUNT: u64 = 20_000;
    let link = Link::default();
    let first = Status::idle(Shard::new(1).unwrap(), volume(), 1, Phase::Serving);
    let deadline = std::time::Instant::now() + PATIENCE;
    let mut taken = Vec::new();
    std::thread::scope(|scope| {
        let publisher = scope.spawn(|| {
            for io in 1..=COUNT {
                while !link.status.publish(Status { io, ..first }) {
                    if std::time::Instant::now() >= deadline {
                        return;
                    }
                    std::thread::yield_now();
                }
            }
        });
        while !publisher.is_finished() {
            taken.extend(link.status.take().map(|status| status.io));
        }
    });
    taken.extend(link.status.take().map(|status| status.io));
    assert!(taken.windows(2).all(|pair| pair[0] < pair[1]), "{taken:?}");
    assert_eq!(taken.last(), Some(&COUNT));
    assert_eq!(link.status.take(), None);
}

#[test]
fn each_message_kind_writes_its_kind_byte_after_version_1() {
    let kinds: Vec<_> = (every_message().iter())
        .map(|message| {
            let bytes = encoded(message);
            (bytes[..2].to_vec(), bytes[2])
        })
        .collect();
    assert!(kinds.iter().all(|(version, _)| version == &[0, 1]));
    let mut seen: Vec<u8> = kinds.iter().map(|(_, kind)| *kind).collect();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(
        seen,
        [1, 2, 3, 4],
        "status 1, nominate 2, peer 3, request 4"
    );
    let status = (every_message().into_iter())
        .find(|message| matches!(message, Message::Status(_)))
        .unwrap();
    assert_eq!(encoded(&status)[2], 1);
    let nominate = Message::Inbound(messages()[0]);
    assert_eq!(encoded(&nominate)[2], 2);
    let peer = Message::Inbound(messages()[2]);
    assert_eq!(encoded(&peer)[2], 3);
    let request = Message::Inbound(messages()[5]);
    assert_eq!(encoded(&request)[2], 4);
}

#[test]
fn a_retried_older_nomination_leaves_the_newer_witness_queued() {
    let link = Link::default();
    let [older, newer] = [messages()[0], messages()[1]];
    assert!(link.inbox.deliver(newer));
    assert!(
        link.inbox.deliver(older),
        "the older witness counts as handled"
    );
    let mut drained = Vec::new();
    link.inbox.drain(|message| drained.push(message));
    assert_eq!(drained, [newer], "the witness with the later expiry stays");
}
