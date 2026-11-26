//! Receive-order and same-poll behavior of the owner's GET handling, driven
//! by authenticated frames injected into one receive burst: each ready GET
//! starts its read in the poll that receives it, in windows of at most
//! `min(batch, BatchMax)` GETs whose keys are hashed once; admission and
//! lookup follow the burst's order around every barrier, rejected frame,
//! stranger, truncated datagram and vacant slot, so a refusal lands before
//! a later duplicate of its request; adjacent PUT DATA frames keep their
//! pairing beside GETs; each GET's lookup spends its own allowance, and an
//! allowance below one lookup's guard bundle and hash charge prepares
//! nothing; and a turn that unwinds
//! mid-receive poisons admission, its unhandled receive leases and lookahead
//! entries are released, and the read it admitted keeps its custody.

use crate::storage::device::Operation;
use crate::storage::owner_fixture::{SimControl, storage_windowed};
use crate::storage::{INTERPOSE, Pause};

use super::frame::{Header, Kind, Status};
use super::owner::OwnerConfig;
use super::owner_tests::OWNER;
use super::put_tests::{Scene, request, scene_over};

/// The window counts of `prepared` windows holding `gets` GETs.
pub(super) fn windows(prepared: u64, gets: u64) -> super::owner::Windows {
    super::owner::Windows { prepared, gets }
}

/// The windows a contiguous run of `frames` eligible GET frames forms under a window capacity of `capacity`, as
/// `(windows, frames in them)`: successive windows of `capacity` frames and a last one of the frames left when they
/// are two or more; none under a capacity below two.
pub(super) fn run_windows(frames: usize, capacity: usize) -> (usize, usize) {
    if capacity < 2 {
        return (0, 0);
    }
    let full = frames / capacity;
    let tail = if frames % capacity >= 2 {
        frames % capacity
    } else {
        0
    };
    (full + usize::from(tail != 0), full * capacity + tail)
}

/// Read commands the windowed volume keeps: the depth less two write slots and the metadata slot.
pub(super) const READ_COMMANDS: usize = 5;

/// Read commands the device has accepted so far.
pub(super) fn submitted(control: &SimControl) -> usize {
    control.accepted(Operation::Read)
}

pub(super) fn config(batch: u32) -> OwnerConfig {
    OwnerConfig {
        batch,
        request_slots: 8,
        peer_requests: 4,
        serve: super::serve::ServeConfig {
            slots: 4,
            ..OWNER.serve
        },
        ..OWNER
    }
}

/// A scene over a storage whose index admits batches of `batch_max` keys,
/// with eight read operation records, and an owner of `batch` datagrams a
/// poll with eight request slots, four per peer.
pub(super) fn windowed(batch: u32, batch_max: usize, body: impl FnOnce(Scene<'_, '_>)) {
    scene_over(
        storage_windowed(batch_max, 8),
        config(batch),
        &super::owner_tests::PRINCIPALS,
        body,
    );
}

/// The statuses of the ERROR frames among `sent`, by request.
pub(super) fn errors(sent: &[Header]) -> Vec<(u64, Status)> {
    sent.iter()
        .filter(|frame| frame.kind == Kind::Error)
        .map(|frame| (frame.request, Status::from_wire(frame.status).unwrap()))
        .collect()
}

/// Injects `count` GETs of the published key 1, slots 0 to 3 from peer 0 and
/// then from peer 1, generation `generation`.
fn inject_hits(scene: &mut Scene<'_, '_>, count: usize, generation: u64) {
    for n in 0..count {
        let peer = n / 4;
        let get = scene.get(peer, request((n % 4) as u16, generation), 1);
        scene.inject(peer, &get);
    }
}

/// Injects the sealed frames `frames` from `peer` back to back as one datagram.
pub(super) fn inject_packed(scene: &mut Scene<'_, '_>, peer: usize, frames: &[Vec<u8>]) {
    scene.nets[peer].borrow_mut().inject(1, &frames.concat());
}

/// Injects the GET frames `headers` from `peer`: one datagram each, or back to back in one packed datagram.
fn inject_gets(scene: &mut Scene<'_, '_>, peer: usize, headers: &[Header], packed: bool) {
    if packed {
        let frames: Vec<Vec<u8>> = headers
            .iter()
            .map(|header| scene.sealed(peer, header, &[], |_| {}))
            .collect();
        inject_packed(scene, peer, &frames);
    } else {
        for header in headers {
            scene.inject(peer, header);
        }
    }
}

/// A qualifying GET submits its read's first command in the poll that
/// receives it, with no later traffic: for every burst width from one to
/// eight, under batches below, equal to and above the index's batch limit
/// and limits of one and zero, the receiving poll prepares its GETs in
/// successive windows of at most `min(batch, limit)`, with a lone GET left
/// to the scalar path, and submits one read command per GET
/// it received while the volume's six read commands last, and the GETs
/// past the batch submit theirs in the polls that receive them. The seventh and eighth
/// GETs of a full burst find every read command taken: each is admitted and
/// waits, holding its right, and submits once a command returns.
#[test]
fn every_ready_get_submits_its_first_command_in_the_receiving_poll() {
    for (batch, batch_max) in [(8, 4), (8, 8), (4, 8), (2, 8), (8, 1), (8, 0)] {
        for width in 1..=8usize {
            windowed(batch, batch_max, |mut scene| {
                let before = submitted(&scene.control);
                let lookups = scene.owner.lookups();
                let windows = scene.owner.windows();
                inject_hits(&mut scene, width, 1);
                scene.polls(1);
                // A receive takes an equal share of the batch from each peer.
                let share = batch as usize / 2;
                let first = width.min(4).min(share) + width.saturating_sub(4).min(share);
                // The receive's GETs are contiguous: they form successive
                // windows of `C = min(batch, limit)`, and a final run of one
                // takes the scalar path.
                let capacity = (batch as usize).min(batch_max);
                let (count, gets) = run_windows(first, capacity);
                let now = scene.owner.windows();
                assert_eq!(
                    (now.prepared - windows.prepared, now.gets - windows.gets),
                    (count as u64, gets as u64),
                    "batch {batch}, limit {batch_max}, width {width}"
                );
                assert_eq!(
                    submitted(&scene.control) - before,
                    first.min(READ_COMMANDS),
                    "batch {batch}, limit {batch_max}, width {width}"
                );
                assert_eq!(scene.owner.lookups() - lookups, first as u64);
                scene.polls(4);
                assert_eq!(
                    submitted(&scene.control) - before,
                    width.min(READ_COMMANDS),
                    "batch {batch}, limit {batch_max}, width {width}"
                );
                assert_eq!(scene.owner.lookups() - lookups, width as u64);
                assert_eq!(scene.owner.census().live(), width as u32);
                scene.turns(40);
                assert!(
                    submitted(&scene.control) - before >= width,
                    "batch {batch}, limit {batch_max}, width {width}"
                );
                assert!(errors(&scene.sent(0)).is_empty());
                assert!(errors(&scene.sent(1)).is_empty());
            });
        }
    }
}

/// The next CANCEL from `peer` for `request`, under the session's fields.
pub(super) fn cancel_frame(scene: &mut Scene<'_, '_>, peer: usize, request: u64) -> Header {
    let get = scene.get(peer, request, 1);
    Header {
        status: Status::Cancelled as u16,
        principal: get.principal,
        key_epoch: get.key_epoch,
        owner_nonce: get.owner_nonce,
        client_nonce: get.client_nonce,
        sequence: get.sequence,
        epoch: get.epoch,
        ..super::serve::header(Kind::Cancel, request, get.key)
    }
}

/// Injects `header` from `peer` sealed under a tag with one byte flipped,
/// so it parses and fails authentication.
fn inject_forged(scene: &mut Scene<'_, '_>, peer: usize, header: &Header) {
    use super::datagram::{HEADER_LEN, PeerId};
    use super::frame::{Direction, encode, mac_input_for, seal};
    let crc = crate::storage::Crc32c::detect();
    let mut encoded = [0u8; HEADER_LEN];
    encode(crc, header, [&[], &[]], &mut encoded).unwrap();
    let input = mac_input_for(
        &encoded,
        [&[], &[]],
        OWNER.endpoint,
        Direction::ClientToOwner,
    )
    .unwrap();
    let mut tag = scene.rings[peer].tag(PeerId(0), &input).unwrap();
    tag[0] ^= 1;
    seal(&mut encoded, tag);
    scene.nets[peer].borrow_mut().inject(1, &encoded);
}

/// A burst that mixes GETs with rejected frames, a replay, a duplicate of
/// a refused request, a CANCEL and a PUT BEGIN keeps every effect at its
/// frame's place in receive order. Peer 0 sends a hit, a miss, an
/// unparseable datagram, the miss's request again under a fresh sequence,
/// a forged GET, a CANCEL of an idle slot, a second hit and that hit's
/// frame replayed; peer 1 sends a hit, a PUT BEGIN and a hit. Only the five
/// session-admitted GETs that reach a read look up, each hit takes its own
/// right and starts its read, the duplicate meets the miss's retained
/// refusal without a lookup or a second ERROR, and the unparseable, forged
/// and replayed frames are dropped.
#[test]
fn a_mixed_burst_keeps_every_effect_in_receive_order() {
    windowed(8, 8, |mut scene| {
        let before = submitted(&scene.control);
        let lookups = scene.owner.lookups();
        let dropped = scene.owner.report().dropped;
        let hit = scene.get(0, request(0, 1), 1);
        scene.inject(0, &hit);
        let miss = scene.get(0, request(1, 1), 9);
        scene.inject(0, &miss);
        scene.nets[0].borrow_mut().inject(1, &[0x5A; 64]);
        let again = scene.get(0, request(1, 1), 9);
        scene.inject(0, &again);
        let forged = scene.get(0, request(2, 1), 1);
        inject_forged(&mut scene, 0, &forged);
        let cancel = cancel_frame(&mut scene, 0, request(3, 1));
        scene.inject(0, &cancel);
        let second = scene.get(0, request(2, 1), 1);
        scene.inject(0, &second);
        scene.inject(0, &second);
        let first = scene.get(1, request(0, 1), 1);
        scene.inject(1, &first);
        let begin = scene.frame(1, Kind::PutBegin, request(1, 1), 6, |_| {});
        scene.inject(1, &begin);
        let last = scene.get(1, request(2, 1), 1);
        scene.inject(1, &last);
        // A receive takes four datagrams from each peer, so peer 0's eight
        // arrive over two polls.
        scene.polls(2);
        assert_eq!(scene.owner.lookups() - lookups, 5);
        assert_eq!(submitted(&scene.control) - before, 4);
        assert_eq!(scene.owner.report().dropped - dropped, 3);
        scene.polls(4);
        assert_eq!(scene.owner.lookups() - lookups, 5);
        let to_first = scene.sent(0);
        assert_eq!(
            errors(&to_first),
            vec![(request(1, 1), Status::Missing)],
            "{to_first:?}"
        );
        let to_second = scene.sent(1);
        assert!(errors(&to_second).is_empty(), "{to_second:?}");
        assert!(
            to_second
                .iter()
                .any(|frame| frame.kind == Kind::PutAuthority),
            "{to_second:?}"
        );
    });
}

/// A frame of each barrier kind between GETs: a CANCEL, a PUT BEGIN, a PUT
/// PREPARE and a PUT CANCEL naming no attempt, a PUT DATA with no upload
/// behind it, a HELLO, a CONFIRM, an ACK of a running read, an
/// unparseable datagram and a forged GET.
#[derive(Debug, Clone, Copy)]
enum Barrier {
    Cancel,
    PutBegin,
    PutPrepare,
    PutCancel,
    PutData,
    Hello,
    Confirm,
    Ack,
    Malformed,
    Forged,
}

/// Injects `barrier` from peer 1, whose session holds the PUT grant, naming
/// request slot 3; an ACK acknowledges the read `start` began there.
fn inject_barrier(scene: &mut Scene<'_, '_>, barrier: Barrier, start: &Header) {
    let at = request(3, 1);
    match barrier {
        Barrier::Cancel => {
            let cancel = cancel_frame(scene, 1, at);
            scene.inject(1, &cancel);
        }
        Barrier::PutBegin => {
            let begin = scene.frame(1, Kind::PutBegin, at, 6, |_| {});
            scene.inject(1, &begin);
        }
        Barrier::PutPrepare | Barrier::PutCancel => {
            let kind = if matches!(barrier, Barrier::PutPrepare) {
                Kind::PutPrepare
            } else {
                Kind::PutCancel
            };
            let frame = scene.frame(1, kind, at, 6, |_| {});
            scene.inject(1, &frame);
        }
        Barrier::PutData => {
            let (header, body) = scene.fragment(at, 7, &[0x3C; 100], 0);
            scene.inject_edited(1, &header, &body, |_| {});
        }
        Barrier::Hello | Barrier::Confirm => {
            // A bootstrap frame's sequence must exceed the peer's bootstrap
            // floor.
            scene.get(1, 0, 1);
            scene.get(1, 0, 1);
            let get = scene.get(1, 0, 1);
            let kind = if matches!(barrier, Barrier::Hello) {
                Kind::Hello
            } else {
                Kind::Confirm
            };
            let header = Header {
                kind,
                principal: get.principal,
                key_epoch: get.key_epoch,
                owner_nonce: if kind == Kind::Hello {
                    [0; 16]
                } else {
                    get.owner_nonce
                },
                client_nonce: get.client_nonce,
                sequence: get.sequence,
                epoch: if kind == Kind::Hello { 0 } else { get.epoch },
                datagram_len: super::frame::BOOTSTRAP_BODY_LEN as u32,
                ..super::serve::header(kind, 0, [0; 32])
            };
            let mut body = [0u8; super::frame::BOOTSTRAP_BODY_LEN];
            body[..4].copy_from_slice(&4u32.to_be_bytes());
            body[4..].copy_from_slice(&4u32.to_be_bytes());
            scene.inject_edited(1, &header, &body, |_| {});
        }
        Barrier::Ack => {
            let get = scene.get(1, start.request, 1);
            let ack = Header {
                kind: Kind::Ack,
                sequence: get.sequence,
                principal: get.principal,
                key_epoch: get.key_epoch,
                owner_nonce: get.owner_nonce,
                client_nonce: get.client_nonce,
                epoch: get.epoch,
                remaining_ms: 0,
                datagram_len: 0,
                index: 0,
                offset: 0,
                grant: get.grant,
                key: get.key,
                ..*start
            };
            scene.inject(1, &ack);
        }
        Barrier::Malformed => scene.nets[1].borrow_mut().inject(1, &[0xA5; 192]),
        Barrier::Forged => {
            let get = scene.get(1, at, 1);
            inject_forged(scene, 1, &get);
        }
    }
}

/// Every barrier kind between GETs leaves the GETs around it to their own
/// handling in the receiving poll. One receive holds two hits, the barrier
/// and two more hits. Each pair of hits forms its own window, except that a
/// forged GET parses as a GET and joins one window of five. All four hits
/// look up once and submit their first command in that poll. The barrier
/// reaches its own handling: PUT BEGIN, PUT PREPARE, PUT CANCEL, HELLO and
/// CONFIRM get their handler's reply, CANCEL and ACK are accepted without a
/// reply, and PUT DATA, the unparseable datagram and the forged GET are
/// dropped. The ACK barrier names a read peer 1 started in an earlier poll.
#[test]
fn every_barrier_kind_leaves_the_gets_around_it_to_the_receiving_poll() {
    for barrier in [
        Barrier::Cancel,
        Barrier::PutBegin,
        Barrier::PutPrepare,
        Barrier::PutCancel,
        Barrier::PutData,
        Barrier::Hello,
        Barrier::Confirm,
        Barrier::Ack,
        Barrier::Malformed,
        Barrier::Forged,
    ] {
        windowed(8, 8, |mut scene| {
            let start = if matches!(barrier, Barrier::Ack) {
                let earlier = scene.get(1, request(3, 1), 1);
                scene.inject(1, &earlier);
                scene.turns(4);
                scene
                    .sent(1)
                    .into_iter()
                    .find(|frame| frame.kind == Kind::Start)
                    .expect("the earlier read's START")
            } else {
                super::serve::header(Kind::Start, 0, [0; 32])
            };
            let before = submitted(&scene.control);
            let lookups = scene.owner.lookups();
            let dropped = scene.owner.report().dropped;
            let windows_before = scene.owner.windows();
            // Peer 0's two hits arrive first, then peer 1's barrier and two
            // hits: the receive holds hit, hit, barrier, hit, hit.
            for slot in 0..2 {
                let get = scene.get(0, request(slot, 1), 1);
                scene.inject(0, &get);
            }
            inject_barrier(&mut scene, barrier, &start);
            for slot in 0..2 {
                let get = scene.get(1, request(slot, 1), 1);
                scene.inject(1, &get);
            }
            derivations();
            scene.polls(1);
            // Each window's keys are hashed once and every lookup reuses its
            // prepared route, the second window's included; the forged GET
            // is hashed in its window and never looked up, and a PUT BEGIN
            // hashes its own key.
            let hashed = if matches!(barrier, Barrier::Forged | Barrier::PutBegin) {
                5
            } else {
                4
            };
            assert_eq!(derivations(), hashed, "{barrier:?}");
            assert_eq!(scene.owner.lookups() - lookups, 4, "{barrier:?}");
            assert_eq!(submitted(&scene.control) - before, 4, "{barrier:?}");
            // A barrier ends one window and the next starts after it; a
            // forged GET parses as a GET, joins the run and is dropped at
            // its authentication.
            let now = scene.owner.windows();
            let formed = (
                now.prepared - windows_before.prepared,
                now.gets - windows_before.gets,
            );
            let expected = if matches!(barrier, Barrier::Forged) {
                (1, 5)
            } else {
                (2, 4)
            };
            assert_eq!(formed, expected, "{barrier:?}");
            // The barrier itself reached its own handling: its handler's
            // reply, a silent acceptance for CANCEL and ACK, or a drop for a
            // frame no handler admits.
            let (drops, reply) = match barrier {
                Barrier::PutBegin => (0, Some(Kind::PutAuthority)),
                Barrier::PutPrepare | Barrier::PutCancel => (0, Some(Kind::PutError)),
                Barrier::Hello => (0, Some(Kind::Challenge)),
                Barrier::Confirm => (0, Some(Kind::Ready)),
                Barrier::Cancel | Barrier::Ack => (0, None),
                Barrier::PutData | Barrier::Malformed | Barrier::Forged => (1, None),
            };
            assert_eq!(scene.owner.report().dropped - dropped, drops, "{barrier:?}");
            let sent = scene.sent(1);
            let replies: Vec<Kind> = sent
                .iter()
                .map(|frame| frame.kind)
                .filter(|kind| *kind != Kind::Start && *kind != Kind::Data)
                .collect();
            assert_eq!(
                replies,
                reply.into_iter().collect::<Vec<_>>(),
                "{barrier:?}"
            );
        });
    }
}

/// Adjacent PUT DATA frames keep their pairing between GET windows: one
/// receive holds peer 0's two hits, then peer 1's two fragments of its
/// ready upload and two hits. Each pair of hits forms a window, all four
/// look up and start in that poll, nothing is dropped, and both fragments
/// are acknowledged.
#[test]
fn adjacent_put_data_keeps_its_pairing_between_gets() {
    use super::geometry::FRAGMENT_LEN;
    windowed(8, 8, |mut scene| {
        let object = super::owner_tests::payload(2 * FRAGMENT_LEN as usize, 33);
        let (at, serial) = super::put_tests::ready_upload(&mut scene, &object);
        scene.sent(1);
        let before = submitted(&scene.control);
        let lookups = scene.owner.lookups();
        let windows_before = scene.owner.windows();
        for slot in 0..2 {
            let get = scene.get(0, request(slot, 1), 1);
            scene.inject(0, &get);
        }
        for index in 0..2 {
            let (header, body) = scene.fragment(at, serial, &object, index);
            scene.inject_edited(1, &header, &body, |_| {});
        }
        for slot in [0, 2] {
            let get = scene.get(1, request(slot, 1), 1);
            scene.inject(1, &get);
        }
        let dropped = scene.owner.report().dropped;
        scene.polls(1);
        assert_eq!(scene.owner.lookups() - lookups, 4);
        assert_eq!(submitted(&scene.control) - before, 4);
        assert_eq!(scene.owner.report().dropped, dropped);
        let now = scene.owner.windows();
        assert_eq!(
            (
                now.prepared - windows_before.prepared,
                now.gets - windows_before.gets
            ),
            (2, 4)
        );
        scene.turns(4);
        let acked: Vec<u32> = scene
            .sent(1)
            .iter()
            .filter(|frame| frame.kind == Kind::PutAck)
            .map(|frame| frame.index)
            .collect();
        assert!(acked.contains(&2), "both fragments acknowledged: {acked:?}");
    });
}

/// The work one key read of a resident object takes on a fresh windowed
/// storage: the lookup's whole charge under `Credit::Read`.
fn hit_charge() -> usize {
    use crate::storage::WorkBudget;
    use crate::storage::owner_fixture::{Device, arena, publish};
    let storage = storage_windowed(8, 8);
    let buffers = arena(16);
    let mut device = Device::new(&storage, &buffers);
    publish(
        &storage,
        &mut device,
        &super::owner_tests::key(1),
        0,
        &[1; 1000],
    );
    let mut reader = storage.register().unwrap();
    let mut budget = WorkBudget::new(1 << 12);
    device
        .volume
        .read_key(
            &mut reader,
            &super::owner_tests::key(1),
            OWNER.lookup_retries,
            &mut budget,
            u64::MAX,
        )
        .unwrap();
    (1 << 12) - budget.remaining()
}

/// Each GET's lookup spends its own allowance of `lookup_work` steps: with
/// exactly one hit's charge, a miss followed by two hits in one burst
/// leaves both hits funded; one step short, the miss, which costs less,
/// still ends `Missing` and every hit is refused `Contended`; with no
/// retries every GET is refused `Contended`.
#[test]
fn each_gets_lookup_spends_its_own_allowance() {
    let charge = hit_charge();
    let cases = [
        (charge, OWNER.lookup_retries, 2),
        (charge - 1, OWNER.lookup_retries, 0),
        (charge, 0, 0),
    ];
    for (work, retries, hits) in cases {
        let config = OwnerConfig {
            lookup_work: work,
            lookup_retries: retries,
            ..config(8)
        };
        scene_over(
            storage_windowed(8, 8),
            config,
            &super::owner_tests::PRINCIPALS,
            |mut scene| {
                let before = submitted(&scene.control);
                let miss = scene.get(0, request(0, 1), 9);
                scene.inject(0, &miss);
                for slot in 1..3 {
                    let get = scene.get(0, request(slot, 1), 1);
                    scene.inject(0, &get);
                }
                scene.polls(4);
                assert_eq!(submitted(&scene.control) - before, hits, "{work} {retries}");
                let mut expected = vec![(
                    request(0, 1),
                    if retries == 0 {
                        Status::Contended
                    } else {
                        Status::Missing
                    },
                )];
                if hits == 0 {
                    expected.extend((1..3).map(|slot| (request(slot, 1), Status::Contended)));
                }
                assert_eq!(errors(&scene.sent(0)), expected, "{work} {retries}");
            },
        );
    }
}

/// Arms a panic at the pin of the lookup after the next `skip` lookups on
/// this thread.
fn panic_at_pin(skip: usize) {
    INTERPOSE.with(|hook| {
        hook.set(Some((
            Pause::Pin,
            Box::new(move || {
                if skip == 0 {
                    panic!("a lookup unwinds at its pin");
                }
                panic_at_pin(skip - 1);
            }),
        )));
    });
}

/// A turn that unwinds in the middle of a receive burst poisons admission
/// and keeps the custody of the read it already admitted. Peer 0 sends
/// three hits; the second's lookup unwinds at its pin. The first read
/// holds its right through the unwind; a later GET is refused
/// `OwnerUnavailable` without a lookup; a re-key is refused `Poisoned`;
/// the first read's request stays live until the closed owner's volume
/// drains its read; and the request whose lookup unwound stays draining.
/// The packed arm sends the three hits as one datagram: the frame after the
/// unwound one is never handled, so two GET frames reached the serve core
/// and the third never does, and the datagram's receive lease is returned.
#[test]
fn an_unwind_mid_receive_poisons_admission_and_keeps_admitted_custody() {
    for packed in [false, true] {
        unwind_mid_receive(packed);
    }
}

fn unwind_mid_receive(packed: bool) {
    windowed(8, 8, |mut scene| {
        let before = submitted(&scene.control);
        let lookups = scene.owner.lookups();
        let leased = scene.owner.report().retained.packets;
        let hits: Vec<Header> = (0..3)
            .map(|slot| scene.get(0, request(slot, 1), 1))
            .collect();
        inject_gets(&mut scene, 0, &hits, packed);
        panic_at_pin(1);
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| scene.polls(1)));
        assert!(unwound.is_err(), "the second lookup unwound the turn");
        // The receive pool holds the leases the receive slots keep and no other: the unwinding turn returned the
        // lease of the datagram it was handling.
        let report = scene.owner.report();
        assert_eq!(
            report.retained.packets as usize,
            leased as usize + scene.owner.held_receive_leases()
        );
        // Two GET frames reached the serve core. The datagram whose frame unwound is not counted as carrying one.
        assert_eq!(
            (report.get_frames, report.get_datagrams),
            (2, u64::from(!packed))
        );
        assert!(INTERPOSE.with(|hook| hook.take().is_none()));
        assert!(scene.owner.poisoned());
        assert_eq!(scene.owner.lookups() - lookups, 1);
        assert_eq!(submitted(&scene.control) - before, 1);
        if packed {
            assert_eq!(scene.owner.held_receive_leases(), 0);
        }
        // The first GET's read and the second GET's request, admitted before
        // its lookup unwound, stay live.
        assert_eq!(scene.owner.census().live(), 2);
        let fresh = [0x55; 32];
        let entry = [super::auth::KeyEntry {
            principal: super::owner_tests::PRINCIPALS[0],
            key: &fresh,
        }];
        assert_eq!(
            scene.owner.rekey(&entry, 2, scene.turn * 100),
            Err(super::owner::OwnerRekeyError::Poisoned)
        );
        let later = scene.get(1, request(0, 1), 1);
        scene.inject(1, &later);
        scene.turns(4);
        assert_eq!(scene.owner.lookups() - lookups, 1);
        assert_eq!(
            errors(&scene.sent(1)),
            vec![(request(0, 1), Status::OwnerUnavailable)]
        );
        if packed {
            // The serve core saw the datagram's first two frames and peer 1's later GET; the datagram's third
            // frame was never handled.
            assert_eq!(scene.owner.report().get_frames, 3);
            assert_eq!(scene.owner.serve_report().requests, 3);
            assert!(errors(&scene.sent(0)).is_empty());
        }
        // Nobody acknowledges the read's frames: its request keeps its
        // custody across turns, and releases only once the closed owner's
        // volume drained it.
        scene.turns(400);
        assert_eq!(scene.owner.census().live(), 2);
        let _ = scene.owner.close(scene.turn * 100);
        let quiesced = (0..5_000).any(|_| {
            scene.turns(1);
            matches!(
                scene.owner.quiesce(),
                Some(crate::storage::QuiesceProgress::Quiesced(_))
            )
        });
        assert!(quiesced, "the volume drained the admitted read");
        // The admitted read's request released; the request whose lookup
        // unwound before any read was bound stays draining under the poison.
        let census = scene.owner.census();
        assert_eq!((census.active, census.draining), (0, 1));
        assert!(
            scene.owner.poisoned(),
            "the poison stays visible after the close"
        );
        assert_eq!(scene.control.outstanding(), 0);
    });
}

/// Derivations on this thread since the last call.
pub(super) fn derivations() -> usize {
    crate::index::DERIVATIONS.with(|count| count.replace(0))
}

/// A window hashes each of its keys once, ahead of that key's lookup, and
/// each lookup starts from its prepared route without hashing again; a
/// lone GET derives its own route. Four hits from one peer form one window of four.
/// The packed arm sends the four hits as one datagram: each frame's key is
/// hashed as often as the same frame's alone.
#[test]
fn a_window_hashes_each_key_once() {
    for packed in [false, true] {
        window_hashes_each_key_once(packed);
    }
}

fn window_hashes_each_key_once(packed: bool) {
    windowed(8, 8, |mut scene| {
        let hits: Vec<Header> = (0..4)
            .map(|slot| scene.get(0, request(slot, 1), 1))
            .collect();
        inject_gets(&mut scene, 0, &hits, packed);
        let before = submitted(&scene.control);
        derivations();
        get_tags();
        scene.polls(1);
        assert_eq!(scene.owner.windows(), windows(1, 4));
        assert_eq!(submitted(&scene.control) - before, 4);
        assert_eq!(derivations(), 4);
        assert_eq!(get_tags(), 4, "each GET frame is tagged once");
        assert!(scene.owner.preparation_is_empty());
        let get = scene.get(1, request(0, 1), 1);
        scene.inject(1, &get);
        scene.polls(1);
        assert_eq!(scene.owner.windows(), windows(1, 4));
        assert_eq!(derivations(), 1);
    });
}

/// An allowance below one lookup's guard bundle and hash charge prepares no
/// window: every GET takes the scalar path and is refused `Contended`
/// before hashing anything.
#[test]
fn an_allowance_below_the_hash_charge_prepares_no_window() {
    let config = OwnerConfig {
        lookup_work: crate::storage::AHEAD - 1,
        ..config(8)
    };
    scene_over(
        storage_windowed(8, 8),
        config,
        &super::owner_tests::PRINCIPALS,
        |mut scene| {
            for slot in 0..4 {
                let get = scene.get(0, request(slot, 1), 1);
                scene.inject(0, &get);
            }
            derivations();
            scene.polls(4);
            assert_eq!(scene.owner.windows(), windows(0, 0));
            assert_eq!(derivations(), 0);
            let expected: Vec<_> = (0..4)
                .map(|slot| (request(slot, 1), Status::Contended))
                .collect();
            assert_eq!(errors(&scene.sent(0)), expected);
        },
    );
}

/// The first call after an unwind that left a window half handled, here
/// the close, releases the receive leases the turn left behind and empties
/// the lookahead: peer 0 sends three hits whose window is prepared, and the
/// second's lookup unwinds, leaving the third datagram's lease in the
/// receive slots and its entry in the lookahead. The packed arm sends the
/// three hits as one datagram, whose one lease the unwinding turn returns:
/// no receive lease stays held, the third frame's entry stays in the
/// lookahead until the close, and the third frame is never handled.
#[test]
fn an_unwind_mid_window_releases_its_receive_leases_and_empties_the_lookahead() {
    for packed in [false, true] {
        unwind_mid_window(packed);
    }
}

fn unwind_mid_window(packed: bool) {
    windowed(8, 8, |mut scene| {
        let hits: Vec<Header> = (0..3)
            .map(|slot| scene.get(0, request(slot, 1), 1))
            .collect();
        let leased = scene.owner.report().retained.packets;
        inject_gets(&mut scene, 0, &hits, packed);
        panic_at_pin(1);
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| scene.polls(1)));
        assert!(unwound.is_err());
        assert_eq!(scene.owner.windows(), windows(1, 3));
        assert_eq!(scene.owner.held_receive_leases(), usize::from(!packed));
        // The receive pool holds the leases the receive slots keep and no other.
        assert_eq!(
            scene.owner.report().retained.packets as usize,
            leased as usize + scene.owner.held_receive_leases()
        );
        assert!(!scene.owner.preparation_is_empty());
        if packed {
            assert_eq!(scene.owner.report().get_frames, 2);
        }
        let _ = scene.owner.close(scene.turn * 100);
        assert_eq!(scene.owner.held_receive_leases(), 0);
        assert!(scene.owner.preparation_is_empty());
        assert!(scene.owner.poisoned());
        // The admitted read keeps its custody until the volume drains it.
        assert_eq!(scene.owner.census().live(), 2);
        let quiesced = (0..5_000).any(|_| {
            scene.turns(1);
            matches!(
                scene.owner.quiesce(),
                Some(crate::storage::QuiesceProgress::Quiesced(_))
            )
        });
        assert!(quiesced);
        if packed {
            assert_eq!(scene.owner.report().get_frames, 2);
            assert_eq!(scene.owner.serve_report().requests, 2);
        }
    });
}

/// Receive order decides between two GETs of one request in one window: a
/// miss and then a hit under a fresh sequence number for the same request.
/// The miss is handled first and the second frame, naming another key,
/// meets its request as a conflict: one lookup, no read, and the ERRORs
/// `Missing` and `ConflictingRequest`. No command is submitted, which tells
/// this order from the hit handled first: that order would start a read and
/// submit its first command.
#[test]
fn a_refusal_lands_before_a_fresh_sequence_duplicate_in_the_same_window() {
    windowed(8, 8, |mut scene| {
        let before = submitted(&scene.control);
        let lookups = scene.owner.lookups();
        let miss = scene.get(0, request(0, 1), 9);
        scene.inject(0, &miss);
        let hit = scene.get(0, request(0, 1), 1);
        scene.inject(0, &hit);
        scene.polls(4);
        assert_eq!(scene.owner.windows(), windows(1, 2));
        assert_eq!(scene.owner.lookups() - lookups, 1);
        assert_eq!(submitted(&scene.control) - before, 0);
        let mut statuses: Vec<Status> = errors(&scene.sent(0))
            .into_iter()
            .map(|(at, status)| {
                assert_eq!(at, request(0, 1));
                status
            })
            .collect();
        statuses.sort_by_key(|status| *status as u16);
        let mut expected = vec![Status::Missing, Status::ConflictingRequest];
        expected.sort_by_key(|status| *status as u16);
        assert_eq!(statuses, expected);
    });
}

/// A datagram from no configured peer, a truncated one and a vacant receive
/// slot each end the window: of five hits whose third is so reported, the
/// first two form a window, the third is dropped with no lookup, and the
/// last two form the next window, all in one poll.
#[test]
fn a_stranger_a_truncated_datagram_and_a_vacant_slot_each_end_the_window() {
    use super::DropReason;
    use super::owner_tests::{RELABEL, Relabel};
    for (relabel, reason) in [
        (Relabel::Stranger, DropReason::NoPeer),
        (Relabel::Truncated, DropReason::Truncated),
        (Relabel::Vacant, DropReason::Vacant),
    ] {
        windowed(8, 8, |mut scene| {
            let before = submitted(&scene.control);
            let lookups = scene.owner.lookups();
            let report = scene.owner.report();
            for slot in 0..4 {
                let get = scene.get(0, request(slot, 1), 1);
                scene.inject(0, &get);
            }
            let get = scene.get(1, request(0, 1), 1);
            scene.inject(1, &get);
            RELABEL.with(|relabels| relabels.borrow_mut().push((2, relabel)));
            scene.polls(1);
            assert_eq!(scene.owner.windows(), windows(2, 4), "{relabel:?}");
            assert_eq!(scene.owner.lookups() - lookups, 4, "{relabel:?}");
            assert_eq!(submitted(&scene.control) - before, 4, "{relabel:?}");
            let after = scene.owner.report();
            assert_eq!(after.dropped - report.dropped, 1, "{relabel:?}");
            assert_eq!(
                after.dropped_by[reason as usize] - report.dropped_by[reason as usize],
                1,
                "{relabel:?}"
            );
        });
    }
}

/// Consecutive receives that put different keys at the same ordinals keep
/// each window's routes to its own keys: two hits of key 1 at ordinals 0
/// and 1, then two GETs of the absent key 9 at the same ordinals in the
/// next receive. The second window's GETs read nothing and are refused
/// `Missing`, each after its own lookup.
#[test]
fn consecutive_windows_at_the_same_ordinals_keep_their_own_keys() {
    windowed(8, 8, |mut scene| {
        for slot in 0..2 {
            let get = scene.get(0, request(slot, 1), 1);
            scene.inject(0, &get);
        }
        scene.polls(1);
        let before = submitted(&scene.control);
        let lookups = scene.owner.lookups();
        for slot in 2..4 {
            let get = scene.get(0, request(slot, 1), 9);
            scene.inject(0, &get);
        }
        scene.polls(1);
        assert_eq!(scene.owner.windows(), windows(2, 4));
        assert_eq!(scene.owner.lookups() - lookups, 2);
        assert_eq!(submitted(&scene.control) - before, 0);
        let missing: Vec<_> = (2..4)
            .map(|slot| (request(slot, 1), Status::Missing))
            .collect();
        scene.polls(2);
        assert_eq!(errors(&scene.sent(0)), missing);
    });
}

fn window_tags() -> usize {
    super::owner::WINDOW_TAGS.with(|count| count.replace(0))
}

/// Hash chains this thread started over client GET headers since the last call: one for each frame a window tags,
/// each frame its own authentication tags, and each GET the fixture seals. A test resets it after sealing its
/// frames and before the owner's poll.
pub(super) fn get_tags() -> usize {
    super::auth::GET_TAGS.with(|count| count.replace(0))
}

/// A window computes a tag only for the frames whose principal and key epoch
/// its ring admits: of four GETs, one naming the next key epoch and one
/// naming another peer's principal keep no tag and are refused, and the two
/// others are tagged once each and start their reads. The packed arm sends
/// the four as one datagram: each frame is tagged as often as the same frame
/// alone, and the two refused frames count in the packed frame account.
#[test]
fn a_window_tags_only_the_frames_its_ring_admits() {
    for packed in [false, true] {
        window_tags_only_admitted_frames(packed);
    }
}

fn window_tags_only_admitted_frames(packed: bool) {
    windowed(8, 8, |mut scene| {
        let before = submitted(&scene.control);
        let lookups = scene.owner.lookups();
        let dropped = scene.owner.report().dropped;
        let first = scene.get(0, request(0, 1), 1);
        let stale = scene.get(0, request(1, 1), 1);
        let stale = Header {
            key_epoch: stale.key_epoch + 1,
            ..stale
        };
        let foreign = scene.get(0, request(2, 1), 1);
        let foreign = Header {
            principal: super::owner_tests::PRINCIPALS[1],
            ..foreign
        };
        let last = scene.get(0, request(3, 1), 1);
        inject_gets(&mut scene, 0, &[first, stale, foreign, last], packed);
        window_tags();
        get_tags();
        scene.polls(1);
        assert_eq!(scene.owner.windows(), windows(1, 4));
        assert_eq!(window_tags(), 2);
        assert_eq!(
            get_tags(),
            2,
            "a frame's handling compares its window tag and computes none"
        );
        assert_eq!(scene.owner.lookups() - lookups, 2);
        assert_eq!(submitted(&scene.control) - before, 2);
        let report = scene.owner.report();
        if packed {
            let unauthenticated = super::DropReason::Unauthenticated as usize;
            assert_eq!(report.packed_dropped_by[unauthenticated], 2);
            assert_eq!(report.dropped, dropped);
        } else {
            assert_eq!(report.dropped - dropped, 2);
        }
        scene.polls(4);
        assert!(errors(&scene.sent(0)).is_empty());
        assert_eq!(scene.owner.census().live(), 2);
    });
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    a_mixed_burst_keeps_every_effect_in_receive_order,
    a_refusal_lands_before_a_fresh_sequence_duplicate_in_the_same_window,
    a_stranger_a_truncated_datagram_and_a_vacant_slot_each_end_the_window,
    a_window_tags_only_the_frames_its_ring_admits,
    an_allowance_below_the_hash_charge_prepares_no_window,
    an_unwind_mid_receive_poisons_admission_and_keeps_admitted_custody,
    an_unwind_mid_window_releases_its_receive_leases_and_empties_the_lookahead,
    consecutive_windows_at_the_same_ordinals_keep_their_own_keys,
    each_gets_lookup_spends_its_own_allowance,
    every_barrier_kind_leaves_the_gets_around_it_to_the_receiving_poll,
    every_ready_get_submits_its_first_command_in_the_receiving_poll,
);
