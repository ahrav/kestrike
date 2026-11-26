//! Packed datagrams at the owner, driven by hand-built datagrams injected into one receive step: a datagram of 2 to
//! `MAX_PACKED_GETS` GET frames back to back from a configured peer is handled as those frames delivered
//! alone, in byte order, in the receiving poll. The shape is decided from the datagram's metadata, length and kind
//! bytes; each frame meets the parse, its own tag and session admission, and a refused frame is dropped alone; one
//! receive step leaves the same serve, session and request state however its GET frames are cut into datagrams;
//! each run of GET frames, lone or packed, forms the windows its length and the window capacity give, and no other
//! frame joins one; one
//! poll handles `batch` packed datagrams of `MAX_PACKED_GETS` frames; each frame moves one frame account; and a copy
//! of a handled packed datagram is refused frame by frame by the session replay window.

use crate::storage::owner_fixture::storage_windowed;

use super::datagram::{HEADER_LEN, MAX_PACKED_GETS, PeerId};
use super::frame::{Header, KIND_AT, Kind, Status};
use super::owner::{DropReason, OwnerConfig, OwnerReport, RetainedCensus};
use super::owner_tests::{PRINCIPALS, RELABEL, Relabel};
use super::put_tests::{Scene, request, scene_over};
use super::window_tests::{
    config, derivations, errors, get_tags, inject_packed, run_windows, submitted, windowed, windows,
};

/// The 192 bytes of `header` as a GET frame from `peer`, tagged under that peer's key.
fn frame(scene: &Scene<'_, '_>, peer: usize, header: &Header) -> Vec<u8> {
    let frame = scene.sealed(peer, header, &[], |_| {});
    assert_eq!(frame.len(), HEADER_LEN);
    frame
}

/// The datagram accounts `(received, handled, dropped)` of `report`.
fn datagrams_of(report: &OwnerReport) -> (u64, u64, u64) {
    (report.received, report.handled, report.dropped)
}

/// The frame accounts of `report`: `get_frames`, `get_datagrams` and the total of `packed_dropped_by`.
fn frames(report: &OwnerReport) -> (u64, u64, u64) {
    (
        report.get_frames,
        report.get_datagrams,
        report.packed_dropped_by.iter().sum(),
    )
}

/// `after` less `before`, by component.
fn moved((a, b, c): (u64, u64, u64), (x, y, z): (u64, u64, u64)) -> (u64, u64, u64) {
    (x - a, y - b, z - c)
}

/// The next `count` GET frames of key `name` from `peer`, at wire slots 0 up and generation `generation`.
fn gets(
    scene: &mut Scene<'_, '_>,
    peer: usize,
    count: u16,
    generation: u64,
    name: u8,
) -> Vec<Vec<u8>> {
    (0..count)
        .map(|slot| {
            let get = scene.get(peer, request(slot, generation), name);
            frame(scene, peer, &get)
        })
        .collect()
}

/// The next canonical ACK from `peer` for `request`, naming a manifest of one 1,000-byte fragment that no read of the
/// owner's sent: the owner admits it to the session and the serve core counts it stale.
fn ack(scene: &mut Scene<'_, '_>, peer: usize, request: u64) -> Header {
    Header {
        kind: Kind::Ack,
        allocation: 5,
        total: 1000,
        body_len: 1000,
        count: 1,
        grant: 1,
        remaining_ms: 0,
        ..scene.get(peer, request, 1)
    }
}

/// A 384-byte datagram of two sealed GET frames from a configured peer is one handled datagram whose two frames are
/// both admitted. The same bytes reported truncated, or from no configured peer, are one `Truncated` or `NoPeer`
/// drop that moves no frame account: the shape reads the transport's report before any byte.
#[test]
fn a_datagram_of_two_get_frames_from_a_configured_peer_is_handled_frame_by_frame() {
    for (relabel, dropped) in [
        (None, None),
        (Some(Relabel::Truncated), Some(DropReason::Truncated)),
        (Some(Relabel::Stranger), Some(DropReason::NoPeer)),
    ] {
        windowed(8, 8, |mut scene| {
            let (before, serve) = (scene.owner.report(), scene.owner.serve_report());
            let pair = gets(&mut scene, 0, 2, 1, 1);
            assert_eq!(pair.concat().len(), 384);
            inject_packed(&mut scene, 0, &pair);
            if let Some(relabel) = relabel {
                RELABEL.with(|relabels| relabels.borrow_mut().push((0, relabel)));
            }
            scene.polls(1);
            let after = scene.owner.report();
            let requests = scene.owner.serve_report().requests - serve.requests;
            match dropped {
                None => {
                    assert_eq!(
                        moved(datagrams_of(&before), datagrams_of(&after)),
                        (1, 1, 0)
                    );
                    assert_eq!(moved(frames(&before), frames(&after)), (2, 1, 0));
                    assert_eq!(requests, 2);
                    assert_eq!(scene.owner.census().live(), 2);
                }
                Some(reason) => {
                    assert_eq!(
                        moved(datagrams_of(&before), datagrams_of(&after)),
                        (1, 0, 1)
                    );
                    assert_eq!(
                        after.dropped_by[reason as usize] - before.dropped_by[reason as usize],
                        1,
                        "{reason:?}"
                    );
                    assert_eq!(moved(frames(&before), frames(&after)), (0, 0, 0));
                    assert_eq!(requests, 0, "{reason:?}");
                }
            }
        });
    }
}

/// Every datagram outside the packed shape is one datagram on the lone path: GET frames with a ragged length of 193,
/// 383, 385 or 484 bytes, a GET frame followed by an ACK frame, and nine GET frames are each one `Malformed` drop
/// that moves no frame account and changes no serve, session or request state. The nine frames are sealed under fresh
/// sequences, so a split into frames would admit them: the first eight sent afterwards as one datagram each pass
/// session admission and reach the serve core.
#[test]
fn a_ragged_length_a_mixed_kind_and_nine_frames_are_each_one_malformed_drop() {
    windowed(8, 8, |mut scene| {
        let nine: Vec<Vec<u8>> = (0..9u16)
            .map(|n| {
                let get = scene.get(0, request(n % 4, 1 + u64::from(n / 4)), 9);
                frame(&scene, 0, &get)
            })
            .collect();
        let pair = gets(&mut scene, 0, 2, 7, 1);
        let two = pair.concat();
        let ack = ack(&mut scene, 0, request(0, 9));
        let ack = scene.sealed(0, &ack, &[], |_| {});
        let get = gets(&mut scene, 0, 1, 8, 1).concat();
        let mut outside = vec![
            two[..193].to_vec(),
            two[..383].to_vec(),
            [&two[..], &[0u8][..]].concat(),
            [&two[..], &[0u8; 100][..]].concat(),
            [get, ack].concat(),
            nine.concat(),
        ];
        let lengths: Vec<usize> = outside.iter().map(Vec::len).collect();
        assert_eq!(lengths, [193, 383, 385, 484, 384, 9 * 192]);
        assert!(nine.len() > MAX_PACKED_GETS);
        let (before, serve) = (scene.owner.report(), scene.owner.serve_report());
        let (sessions, census) = (scene.owner.session_report(), scene.owner.census());
        for datagram in outside.drain(..) {
            scene.nets[0].borrow_mut().inject(1, &datagram);
        }
        // A receive takes four datagrams from one peer, so the six arrive over two polls.
        scene.polls(2);
        let after = scene.owner.report();
        assert_eq!(
            moved(datagrams_of(&before), datagrams_of(&after)),
            (6, 0, 6)
        );
        let malformed = DropReason::Malformed as usize;
        assert_eq!(
            after.dropped_by[malformed] - before.dropped_by[malformed],
            6
        );
        assert_eq!(moved(frames(&before), frames(&after)), (0, 0, 0));
        assert_eq!(scene.owner.serve_report(), serve);
        assert_eq!(scene.owner.session_report(), sessions);
        assert_eq!(scene.owner.census(), census);
        assert!(scene.sent(0).is_empty());
        inject_packed(&mut scene, 0, &nine[..8]);
        scene.polls(1);
        let last = scene.owner.report();
        assert_eq!(moved(datagrams_of(&after), datagrams_of(&last)), (1, 1, 0));
        assert_eq!(moved(frames(&after), frames(&last)), (8, 1, 0));
        assert_eq!(scene.owner.session_report(), sessions);
    });
}

/// A chunk of another kind strictly inside a datagram of GET frames keeps the datagram off the packed path: a
/// sealed ACK between two sealed GETs, and a sealed ACK third of four chunks, are each one `Malformed` drop that
/// moves no frame account and changes no serve, session or request state. Every chunk is sealed under a fresh
/// sequence, so a shape test that read only the first and last kind bytes, or only the first two, would admit the
/// GETs.
#[test]
fn a_chunk_of_another_kind_inside_a_datagram_of_get_frames_is_one_malformed_drop() {
    windowed(8, 8, |mut scene| {
        let sealed = |scene: &mut Scene<'_, '_>, kinds: &[Kind]| -> Vec<u8> {
            let mut datagram = Vec::new();
            for (slot, kind) in kinds.iter().enumerate() {
                let header = match kind {
                    Kind::Get => scene.get(0, request(slot as u16, 1), 1),
                    _ => ack(scene, 0, request(slot as u16, 9)),
                };
                datagram.extend(scene.sealed(0, &header, &[], |_| {}));
            }
            datagram
        };
        let three = sealed(&mut scene, &[Kind::Get, Kind::Ack, Kind::Get]);
        let four = sealed(&mut scene, &[Kind::Get, Kind::Get, Kind::Ack, Kind::Get]);
        assert_eq!((three.len(), four.len()), (3 * 192, 4 * 192));
        for datagram in [&three, &four] {
            let kinds: Vec<u8> = datagram
                .chunks(HEADER_LEN)
                .map(|chunk| chunk[KIND_AT])
                .collect();
            let (first, last) = (kinds[0], kinds[kinds.len() - 1]);
            assert_eq!((first, last), (Kind::Get as u8, Kind::Get as u8));
            assert_eq!(
                kinds[1..kinds.len() - 1]
                    .iter()
                    .filter(|&&kind| kind == Kind::Ack as u8)
                    .count(),
                1
            );
        }
        let (before, serve) = (scene.owner.report(), scene.owner.serve_report());
        let (sessions, census) = (scene.owner.session_report(), scene.owner.census());
        scene.nets[0].borrow_mut().inject(1, &three);
        scene.nets[0].borrow_mut().inject(1, &four);
        scene.polls(1);
        let after = scene.owner.report();
        assert_eq!(
            moved(datagrams_of(&before), datagrams_of(&after)),
            (2, 0, 2)
        );
        let malformed = DropReason::Malformed as usize;
        assert_eq!(
            after.dropped_by[malformed] - before.dropped_by[malformed],
            2
        );
        assert_eq!(moved(frames(&before), frames(&after)), (0, 0, 0));
        assert_eq!(scene.owner.serve_report(), serve);
        assert_eq!(scene.owner.session_report(), sessions);
        assert_eq!(scene.owner.census(), census);
        assert!(scene.sent(0).is_empty());
    });
}

/// A frame refused at the head of a packed datagram is dropped alone, and the hit behind it reaches the serve core
/// and submits its read's first command in the receiving poll. The head is a GET for a key the owner does not hold:
/// in one arm its magic changed before sealing, so it fails the parse and counts under `Malformed`; in the other one
/// tag byte is flipped, so it parses, fails its tag and counts under `Unauthenticated`. The datagram keeps both GET
/// kind bytes, so it is handled. Under a capacity of eight the flipped frame meets the tag its window computed, and
/// under a capacity of one the tag its own handling computes.
#[test]
fn a_refused_first_frame_is_dropped_alone_and_the_frame_after_it_is_served() {
    for reason in [DropReason::Malformed, DropReason::Unauthenticated] {
        for capacity in [8, 1] {
            windowed(8, capacity, |mut scene| {
                let (before, reads) = (scene.owner.report(), submitted(&scene.control));
                let head = scene.get(0, request(0, 1), 9);
                let head = scene.sealed(0, &head, &[], |encoded| {
                    if reason == DropReason::Malformed {
                        encoded[0] ^= 1;
                    }
                });
                let mut head = head;
                if reason == DropReason::Unauthenticated {
                    head[TAG_AT] ^= 1;
                }
                let hit = scene.get(0, request(1, 1), 1);
                let hit = frame(&scene, 0, &hit);
                assert_eq!(head.len(), HEADER_LEN);
                assert_eq!(head[KIND_AT], Kind::Get as u8);
                inject_packed(&mut scene, 0, &[head, hit]);
                scene.polls(1);
                let at = format!("{reason:?}, capacity {capacity}");
                let after = scene.owner.report();
                assert_eq!(
                    moved(datagrams_of(&before), datagrams_of(&after)),
                    (1, 1, 0),
                    "{at}"
                );
                assert_eq!(after.dropped_by, before.dropped_by, "{at}");
                assert_eq!(moved(frames(&before), frames(&after)), (1, 1, 1), "{at}");
                assert_eq!(
                    after.packed_dropped_by[reason as usize]
                        - before.packed_dropped_by[reason as usize],
                    1,
                    "{at}"
                );
                let formed = if capacity == 8 && reason == DropReason::Unauthenticated {
                    windows(1, 2)
                } else {
                    windows(0, 0)
                };
                assert_eq!(scene.owner.windows(), formed, "{at}");
                assert_eq!(scene.owner.serve_report().requests, 1, "{at}");
                assert_eq!(submitted(&scene.control) - reads, 1, "{at}");
                scene.polls(3);
                assert!(errors(&scene.sent(0)).is_empty(), "{at}");
            });
        }
    }
}

/// A frame that fails the parse ends the window before it, and the next window starts at the frame after it: two
/// hits, a GET whose magic changed before sealing, and two hits in one datagram form two windows of two under a
/// capacity of eight. All four hits submit their first commands in the receiving poll, and the middle frame counts
/// alone under `Malformed`.
#[test]
fn a_window_starts_again_after_a_malformed_frame_inside_a_packed_datagram() {
    windowed(8, 8, |mut scene| {
        let (before, reads) = (scene.owner.report(), submitted(&scene.control));
        let mut five = gets(&mut scene, 0, 2, 1, 1);
        let broken = scene.get(0, request(0, 9), 9);
        five.push(scene.sealed(0, &broken, &[], |encoded| encoded[0] ^= 1));
        for slot in 2..4 {
            let hit = scene.get(0, request(slot, 1), 1);
            five.push(frame(&scene, 0, &hit));
        }
        assert!(five.iter().all(|chunk| chunk[KIND_AT] == Kind::Get as u8));
        inject_packed(&mut scene, 0, &five);
        scene.polls(1);
        let after = scene.owner.report();
        assert_eq!(scene.owner.windows(), windows(2, 4));
        assert_eq!(
            moved(datagrams_of(&before), datagrams_of(&after)),
            (1, 1, 0)
        );
        assert_eq!(after.dropped_by, before.dropped_by);
        assert_eq!(moved(frames(&before), frames(&after)), (4, 1, 1));
        let malformed = DropReason::Malformed as usize;
        assert_eq!(
            after.packed_dropped_by[malformed] - before.packed_dropped_by[malformed],
            1
        );
        assert_eq!(submitted(&scene.control) - reads, 4);
    });
}

/// A PUT DATA datagram whose length is a whole number of 192-byte frames, and whose every chunk after the header
/// carries the GET kind byte at the kind offset, is one fragment: the first chunk's kind byte says PUT DATA, so the
/// shape is false and the datagram reaches the PUT core whole. The datagrams are 384 and 1,536 bytes, the header
/// beside a body of one and of seven chunks, each the single fragment of a ready upload, which the owner publishes.
#[test]
fn a_put_data_datagram_of_whole_frames_with_get_kind_bytes_is_one_fragment() {
    for chunks in [1, 7] {
        windowed(8, 8, |mut scene| {
            let mut object = super::owner_tests::payload(chunks * HEADER_LEN, 41);
            for chunk in object.chunks_mut(HEADER_LEN) {
                chunk[KIND_AT] = Kind::Get as u8;
            }
            let (at, serial) = super::put_tests::ready_upload(&mut scene, &object);
            scene.sent(1);
            let (header, body) = scene.fragment(at, serial, &object, 0);
            let datagram = scene.sealed(1, &header, &body, |_| {});
            assert_eq!(datagram.len(), (chunks + 1) * HEADER_LEN);
            assert!((2..=MAX_PACKED_GETS).contains(&(chunks + 1)));
            assert_eq!(datagram[KIND_AT], Kind::PutData as u8);
            assert!(
                datagram[HEADER_LEN..]
                    .chunks(HEADER_LEN)
                    .all(|chunk| chunk[KIND_AT] == Kind::Get as u8)
            );
            let before = scene.owner.report();
            scene.nets[1].borrow_mut().inject(1, &datagram);
            scene.polls(1);
            let after = scene.owner.report();
            assert_eq!(
                moved(datagrams_of(&before), datagrams_of(&after)),
                (1, 1, 0)
            );
            assert_eq!(moved(frames(&before), frames(&after)), (0, 0, 0));
            scene.turns(40);
            let replies = scene.sent(1);
            assert!(
                replies.iter().any(|reply| reply.kind == Kind::PutResult),
                "{replies:?}"
            );
            assert_eq!(scene.fetch(5), object);
        });
    }
}

/// The shape is false for every committed frame vector and golden frame: each, delivered from a configured peer,
/// moves one datagram account and no frame account. A datagram of the packed shape would count as handled and move
/// one frame account per frame, whatever its tags.
#[test]
fn no_frame_vector_or_golden_has_the_packed_shape() {
    let vectors = super::frame::tests::vectors();
    let goldens = super::frame_tests::goldens();
    let inputs: Vec<(&str, Vec<u8>)> = vectors
        .into_iter()
        .chain(goldens.into_iter().map(|(name, raw)| (name, raw.bytes())))
        .collect();
    windowed(8, 8, |mut scene| {
        for (name, bytes) in &inputs {
            let before = scene.owner.report();
            scene.nets[0].borrow_mut().inject(1, bytes);
            scene.polls(1);
            let after = scene.owner.report();
            let (received, handled, dropped) = moved(datagrams_of(&before), datagrams_of(&after));
            assert_eq!((received, handled + dropped), (1, 1), "{name}");
            assert_eq!(moved(frames(&before), frames(&after)), (0, 0, 0), "{name}");
        }
    });
}

/// Frames of one packed datagram take effect in byte order: a miss on request `r` and then a hit on `r` under a
/// fresh sequence give `Missing` and `ConflictingRequest`, with one lookup and no read command. The hit handled
/// first would start a read and submit its first command.
#[test]
fn a_miss_and_a_hit_on_one_request_in_one_datagram_conflict_in_byte_order() {
    windowed(8, 8, |mut scene| {
        let before = submitted(&scene.control);
        let lookups = scene.owner.lookups();
        let miss = scene.get(0, request(0, 1), 9);
        let hit = scene.get(0, request(0, 1), 1);
        let pair = [frame(&scene, 0, &miss), frame(&scene, 0, &hit)];
        inject_packed(&mut scene, 0, &pair);
        scene.polls(1);
        assert_eq!(scene.owner.lookups() - lookups, 1);
        let formed = scene.owner.windows();
        scene.polls(3);
        assert_eq!(scene.owner.lookups() - lookups, 1);
        assert_eq!(submitted(&scene.control) - before, 0);
        // The conflict leaves through the reply ring and the miss through its request, so send order is not
        // handling order. Either frame order looks up once; a hit handled first would submit a read command and
        // send no `Missing`.
        let mut statuses = errors(&scene.sent(0));
        statuses.sort_by_key(|(_, status)| *status as u16);
        let mut expected = [
            (request(0, 1), Status::Missing),
            (request(0, 1), Status::ConflictingRequest),
        ];
        expected.sort_by_key(|(_, status)| *status as u16);
        assert_eq!(statuses, expected);
        assert_eq!(formed, windows(1, 2), "the pair formed a window");
    });
}

/// Four hits in one packed datagram each look up and submit their read's first command in the receiving poll, within
/// the peer's share of four and the volume's five read commands, under a window capacity of eight, which holds the
/// datagram in one window, and of two, which cuts it into two windows. No receive lease and no lookahead entry
/// remains after the poll.
#[test]
fn every_hit_of_a_packed_datagram_submits_its_first_command_in_the_receiving_poll() {
    for (capacity, formed) in [(8, windows(1, 4)), (2, windows(2, 4))] {
        windowed(8, capacity, |mut scene| {
            let before = submitted(&scene.control);
            let lookups = scene.owner.lookups();
            let leased = scene.owner.report().retained.packets;
            let hits = gets(&mut scene, 0, 4, 1, 1);
            assert!(hits.len() <= super::window_tests::READ_COMMANDS);
            assert_eq!(config(8).peer_requests, 4);
            inject_packed(&mut scene, 0, &hits);
            scene.polls(1);
            assert_eq!(scene.owner.windows(), formed, "capacity {capacity}");
            assert_eq!(scene.owner.lookups() - lookups, 4, "capacity {capacity}");
            assert_eq!(submitted(&scene.control) - before, 4, "capacity {capacity}");
            assert_eq!(scene.owner.census().live(), 4);
            assert_eq!(scene.owner.report().retained.packets, leased);
            assert_eq!(scene.owner.held_receive_leases(), 0);
            assert!(scene.owner.preparation_is_empty());
            scene.polls(3);
            assert!(errors(&scene.sent(0)).is_empty());
        });
    }
}

/// A receive window runs across datagram boundaries, and a window that ends inside a packed datagram is followed
/// by one that starts at that datagram's next frame. Each layout is four hits in one receive step, cut into
/// datagrams of the listed frame counts from the listed peers. Under a capacity of eight one window holds all four;
/// under a capacity of two the second window starts where the first ended, inside a packed datagram or at the next
/// datagram; under a capacity of three one window holds three frames, whose chains hash as one group, and the
/// fourth takes the scalar path; under a capacity of one no window forms and every frame takes the scalar path. The
/// last two layouts put frames of both peers in one tag group. In each case every frame is tagged once, under its
/// own peer's key, and starts its read in the receiving poll, and the receive pool holds no lease after it.
#[test]
fn a_window_crosses_datagram_boundaries_and_restarts_inside_a_packed_datagram() {
    // Each layout lists its datagrams as (peer, frames).
    let layouts: [&[(usize, u16)]; 4] = [
        &[(0, 1), (0, 2), (0, 1)],
        &[(0, 3), (0, 1)],
        &[(0, 2), (1, 2)],
        &[(0, 3), (1, 1)],
    ];
    for layout in layouts {
        for (capacity, formed) in [
            (8, windows(1, 4)),
            (3, windows(1, 3)),
            (2, windows(2, 4)),
            (1, windows(0, 0)),
        ] {
            windowed(8, capacity, |mut scene| {
                let (reads, lookups) = (submitted(&scene.control), scene.owner.lookups());
                let before = scene.owner.report();
                let mut slots = [0u16; 2];
                for &(peer, count) in layout {
                    let hits: Vec<Vec<u8>> = (0..count)
                        .map(|_| {
                            let get = scene.get(peer, request(slots[peer], 1), 1);
                            slots[peer] += 1;
                            frame(&scene, peer, &get)
                        })
                        .collect();
                    inject_packed(&mut scene, peer, &hits);
                }
                get_tags();
                scene.polls(1);
                let at = format!("layout {layout:?}, capacity {capacity}");
                let after = scene.owner.report();
                assert_eq!(
                    after.received - before.received,
                    layout.len() as u64,
                    "one receive step takes every datagram: {at}"
                );
                assert_eq!(scene.owner.windows(), formed, "{at}");
                assert_eq!(get_tags(), 4, "{at}");
                assert_eq!(after.get_frames - before.get_frames, 4, "{at}");
                assert_eq!(after.packed_dropped_by, before.packed_dropped_by, "{at}");
                assert_eq!(after.dropped, before.dropped, "{at}");
                assert_eq!(scene.owner.lookups() - lookups, 4, "{at}");
                assert_eq!(submitted(&scene.control) - reads, 4, "{at}");
                assert_eq!(after.retained.packets, before.retained.packets, "{at}");
                assert_eq!(scene.owner.held_receive_leases(), 0);
                assert!(scene.owner.preparation_is_empty());
            });
        }
    }
}

/// One datagram of a receive step in [`a_window_forms_over_each_run_of_get_frames_and_nowhere_else`].
#[derive(Debug, Clone, Copy)]
enum Shape {
    /// One GET hit alone in its datagram.
    Lone,
    /// Two GET hits back to back in one packed datagram.
    Pair,
    /// An ACK the serve core counts stale, which ends a run of GET frames.
    Ack,
}

impl Shape {
    /// GET frames the datagram carries.
    fn gets(self) -> usize {
        match self {
            Shape::Lone => 1,
            Shape::Pair => 2,
            Shape::Ack => 0,
        }
    }
}

/// The windows one receive step of `shapes` forms under a window capacity of `capacity`: the sum of
/// [`run_windows`] over the maximal runs of GET frames, lone or packed, that the ACKs separate.
fn windows_over(shapes: &[Shape], capacity: usize) -> super::owner::Windows {
    let (mut prepared, mut gets) = (0, 0);
    for run in shapes.split(|shape| matches!(shape, Shape::Ack)) {
        let frames = run.iter().map(|shape| shape.gets()).sum();
        let (windows, held) = run_windows(frames, capacity);
        prepared += windows;
        gets += held;
    }
    windows(prepared as u64, gets as u64)
}

/// The windows of a receive step are those of its runs of GET frames, wherever a run ends. Every receive step of
/// one to four datagrams from one peer, each datagram a lone GET, a packed datagram of two GETs or an ACK, runs
/// under window capacities of eight, three, two and one; a step with an ACK holds at most three GET frames and a
/// step without one at most four. The windows that form are those of [`windows_over`]. A lone GET that no earlier
/// window holds starts a window when a GET frame follows it in the next slot, lone or packed, and the capacity is
/// two or more; it starts none in the batch's last slot, before an ACK or under a capacity of one. A lone GET in
/// any of those places that an earlier window holds is handled inside that window. Every GET frame is tagged once,
/// derives its key's route once, reaches the serve core and starts its read in the receiving poll, and every
/// datagram with a GET frame counts once in `get_datagrams`.
#[test]
fn a_window_forms_over_each_run_of_get_frames_and_nowhere_else() {
    const SHAPES: [Shape; 3] = [Shape::Lone, Shape::Pair, Shape::Ack];
    let mut steps = 0;
    for length in 1..=4u32 {
        for code in 0..3usize.pow(length) {
            let shapes: Vec<Shape> = (0..length)
                .map(|at| SHAPES[code / 3usize.pow(at) % 3])
                .collect();
            let gets: usize = shapes.iter().map(|shape| shape.gets()).sum();
            // Every ACK names wire slot 3, so a step with an ACK keeps its GETs in wire slots 0 to 2.
            let acks = shapes.iter().any(|shape| matches!(shape, Shape::Ack));
            if gets > 4 || (acks && gets > 3) {
                continue;
            }
            steps += 1;
            let get_datagrams = shapes.iter().filter(|shape| shape.gets() > 0).count();
            for capacity in [8, 3, 2, 1] {
                windowed(8, capacity, |mut scene| {
                    let (reads, lookups) = (submitted(&scene.control), scene.owner.lookups());
                    let before = scene.owner.report();
                    let mut slot = 0;
                    for shape in &shapes {
                        if matches!(shape, Shape::Ack) {
                            let ack = ack(&mut scene, 0, request(3, 1));
                            scene.inject(0, &ack);
                            continue;
                        }
                        let hits: Vec<Vec<u8>> = (0..shape.gets())
                            .map(|_| {
                                let get = scene.get(0, request(slot, 1), 1);
                                slot += 1;
                                frame(&scene, 0, &get)
                            })
                            .collect();
                        inject_packed(&mut scene, 0, &hits);
                    }
                    get_tags();
                    derivations();
                    scene.polls(1);
                    let at = format!("{shapes:?}, capacity {capacity}");
                    let after = scene.owner.report();
                    assert_eq!(
                        after.received - before.received,
                        shapes.len() as u64,
                        "one receive step takes every datagram: {at}"
                    );
                    assert_eq!(
                        scene.owner.windows(),
                        windows_over(&shapes, capacity),
                        "{at}"
                    );
                    assert_eq!(get_tags(), gets, "{at}");
                    assert_eq!(derivations(), gets, "{at}");
                    assert_eq!(
                        (
                            after.get_frames - before.get_frames,
                            after.get_datagrams - before.get_datagrams
                        ),
                        (gets as u64, get_datagrams as u64),
                        "{at}"
                    );
                    assert_eq!(after.handled - before.handled, shapes.len() as u64, "{at}");
                    assert_eq!(after.dropped, before.dropped, "{at}");
                    assert_eq!(after.packed_dropped_by, before.packed_dropped_by, "{at}");
                    assert_eq!(scene.owner.lookups() - lookups, gets as u64, "{at}");
                    assert_eq!(submitted(&scene.control) - reads, gets, "{at}");
                    assert_eq!(scene.owner.held_receive_leases(), 0, "{at}");
                    assert!(scene.owner.preparation_is_empty(), "{at}");
                });
            }
        }
    }
    assert_eq!(
        steps, 64,
        "59 steps of at most three GET frames and 5 of four without an ACK"
    );
}

/// A window of two to eight frames computes one tag for each of its frames, whichever groups its width breaks into:
/// four frames' chains together while four remain, then the last three, two or one. Each width arrives as one packed
/// datagram of misses and forms one window. Every frame authenticates under the tag its group computed for it and
/// reaches the serve core, and no frame is tagged a second time when it is handled.
#[test]
fn a_window_of_each_width_tags_every_frame_once_and_admits_it() {
    for width in 2..=MAX_PACKED_GETS as u16 {
        windowed(8, 8, |mut scene| {
            let misses: Vec<Vec<u8>> = (0..width)
                .map(|n| {
                    let get = scene.get(0, request(n % 4, 1 + u64::from(n / 4)), 9);
                    frame(&scene, 0, &get)
                })
                .collect();
            inject_packed(&mut scene, 0, &misses);
            let (before, formed) = (scene.owner.report(), scene.owner.windows());
            super::owner::WINDOW_TAGS.with(|count| count.set(0));
            get_tags();
            scene.polls(1);
            let after = scene.owner.report();
            assert_eq!(
                moved(frames(&before), frames(&after)),
                (u64::from(width), 1, 0),
                "width {width}"
            );
            let now = scene.owner.windows();
            assert_eq!(
                (now.prepared - formed.prepared, now.gets - formed.gets),
                (1, u64::from(width)),
                "one window holds the datagram: width {width}"
            );
            assert_eq!(
                super::owner::WINDOW_TAGS.with(std::cell::Cell::get),
                usize::from(width),
                "width {width}"
            );
            assert_eq!(get_tags(), usize::from(width), "width {width}");
        });
    }
}

/// A frame its ring does not admit keeps no tag, and the other two frames of its group of three are tagged once each
/// and admitted. A datagram of three frames and one of seven each hold such a frame, a GET that names another peer's
/// principal, in the middle of the last three: it is refused unauthenticated alone, and every other frame reaches
/// the serve core under the tag the window computed for it.
#[test]
fn a_refused_frame_in_a_group_of_three_leaves_the_other_two_tagged() {
    for width in [3u16, 7] {
        windowed(8, 8, |mut scene| {
            let foreign = usize::from(width) - 2;
            let sealed: Vec<Vec<u8>> = (0..width)
                .map(|n| {
                    let get = scene.get(0, request(n % 4, 1 + u64::from(n / 4)), 9);
                    let principal = if usize::from(n) == foreign {
                        PRINCIPALS[1]
                    } else {
                        get.principal
                    };
                    frame(&scene, 0, &Header { principal, ..get })
                })
                .collect();
            inject_packed(&mut scene, 0, &sealed);
            let before = scene.owner.report();
            super::owner::WINDOW_TAGS.with(|count| count.set(0));
            get_tags();
            scene.polls(1);
            let after = scene.owner.report();
            assert_eq!(
                moved(frames(&before), frames(&after)),
                (u64::from(width) - 1, 1, 1),
                "width {width}"
            );
            let unauthenticated = DropReason::Unauthenticated as usize;
            assert_eq!(
                after.packed_dropped_by[unauthenticated]
                    - before.packed_dropped_by[unauthenticated],
                1,
                "width {width}"
            );
            assert_eq!(
                super::owner::WINDOW_TAGS.with(std::cell::Cell::get),
                usize::from(width) - 1,
                "width {width}"
            );
            assert_eq!(get_tags(), usize::from(width) - 1, "width {width}");
        });
    }
}

/// The header crc folds this thread ran: one for each header `parse` checks through its crc and one for each header
/// an encoder seals, on a CPU that runs the aarch64 or the x86_64 fold.
fn header_folds() -> usize {
    use crate::isa_witness::{Kernel, runs};
    runs(Kernel::CrcLanes) + runs(Kernel::CrcChains)
}

/// Whether this CPU runs a header crc fold that counts itself.
fn folds_are_counted() -> bool {
    use crate::isa_witness::detected;
    detected!(aarch64: "crc", "aes").present || detected!(x86_64: "sse4.2", "pclmulqdq").present
}

/// A window scan that starts in a packed datagram keeps the frame each of that datagram's chunks parsed to, and the
/// frame's handling reads it, so such a frame is parsed once. A frame that the window of an earlier datagram holds is
/// parsed by that scan and again when it is handled, and so is a lone GET. Each case lists the datagrams of one
/// receive step by their frame counts and the parses of the poll that receives their copies. The copies arrive after
/// the first delivery's misses ended, so the session replay window refuses every frame after its parse and its tag,
/// the poll encodes no frame, and each header crc fold of the poll is one parse.
#[test]
fn a_frame_scanned_from_its_own_packed_datagram_is_parsed_once() {
    let cases: [(&[u16], usize); 4] = [
        (&[4], 4),
        (&[3, 3], 3 + 2 * 3),
        (&[2, 1], 2 + 2),
        (&[1, 1], 2 * 2),
    ];
    for (shape, parses) in cases {
        windowed(8, 8, |mut scene| {
            let mut sent = 0;
            let datagrams: Vec<Vec<Vec<u8>>> = shape
                .iter()
                .map(|&count| {
                    (0..count)
                        .map(|_| {
                            let get = scene.get(0, request(sent % 4, 1 + u64::from(sent / 4)), 9);
                            sent += 1;
                            frame(&scene, 0, &get)
                        })
                        .collect()
                })
                .collect();
            let all = u64::from(sent);
            for datagram in &datagrams {
                inject_packed(&mut scene, 0, datagram);
            }
            scene.polls(1);
            assert_eq!(
                scene.owner.report().get_frames,
                all,
                "premise: the session admitted every frame: {shape:?}"
            );
            // The misses end and their replies leave before the copies arrive.
            scene.turns(700);
            assert_eq!(scene.owner.census().live(), 0, "{shape:?}");
            for datagram in &datagrams {
                inject_packed(&mut scene, 0, datagram);
            }
            for net in &scene.nets {
                net.borrow_mut().advance(scene.turn);
            }
            let (before, duplicates) =
                (scene.owner.report(), scene.owner.session_report().duplicate);
            let folds = header_folds();
            scene.owner.poll(scene.turn * 100);
            let folds = header_folds() - folds;
            scene.turn += 1;
            let after = scene.owner.report();
            assert_eq!(
                after.received - before.received,
                shape.len() as u64,
                "premise: one receive step takes every copy: {shape:?}"
            );
            assert_eq!(
                scene.owner.session_report().duplicate - duplicates,
                all,
                "premise: every copy passes its parse and its tag: {shape:?}"
            );
            assert_eq!(
                after.sent, before.sent,
                "premise: the poll encodes no frame: {shape:?}"
            );
            let expected = if folds_are_counted() { parses } else { 0 };
            assert_eq!(folds, expected, "{shape:?}");
        });
    }
}

/// The tag field of a sealed frame starts where its authenticated bytes end.
const TAG_AT: usize = super::frame::AUTHENTICATED_LEN;

/// A frame sent twice in one datagram is served once: the copy is refused by the session replay window as a
/// duplicate and counts under `Session` in the packed frame account.
#[test]
fn a_frame_repeated_in_its_datagram_is_served_once() {
    windowed(8, 8, |mut scene| {
        let (before, sessions) = (scene.owner.report(), scene.owner.session_report());
        let serve = scene.owner.serve_report();
        let once = gets(&mut scene, 0, 1, 1, 1).concat();
        inject_packed(&mut scene, 0, &[once.clone(), once]);
        scene.polls(1);
        let after = scene.owner.report();
        assert_eq!(
            moved(datagrams_of(&before), datagrams_of(&after)),
            (1, 1, 0)
        );
        assert_eq!(moved(frames(&before), frames(&after)), (1, 1, 1));
        let session = DropReason::Session as usize;
        assert_eq!(after.packed_dropped_by[session], 1);
        let now = scene.owner.session_report();
        assert_eq!(now.duplicate - sessions.duplicate, 1);
        let served = scene.owner.serve_report();
        assert_eq!(
            (served.requests - serve.requests, served.duplicates),
            (1, serve.duplicates)
        );
    });
}

/// Each frame of a packed datagram passes the parse, its own tag and session admission, and a frame that fails one is
/// dropped alone. One datagram holds, in order: a hit; a canonical GET whose tag field holds that hit's tag; a GET
/// with one tag byte flipped; a GET sealed under another peer's key; a copy of the first frame, whose sequence the
/// session already admitted; and a hit. The two hits start their reads, three frames count under `Unauthenticated`
/// and one under `Session`. The window capacity of two is below the frame count, so every window boundary falls
/// inside the datagram, and the capacity of eight holds all six frames in one window.
#[test]
fn a_refused_frame_is_dropped_alone_under_its_own_reason() {
    for capacity in [2, 8] {
        windowed(8, capacity, |mut scene| {
            let before = scene.owner.report();
            let reads = submitted(&scene.control);
            let first = gets(&mut scene, 0, 1, 1, 1).concat();
            let borrowed = scene.get(0, request(1, 1), 1);
            let mut borrowed = frame(&scene, 0, &borrowed);
            borrowed[TAG_AT..].copy_from_slice(&first[TAG_AT..]);
            let flipped = scene.get(0, request(1, 1), 1);
            let mut flipped = frame(&scene, 0, &flipped);
            flipped[TAG_AT] ^= 1;
            let foreign = scene.get(0, request(1, 1), 1);
            let foreign = frame(&scene, 1, &foreign);
            let last = scene.get(0, request(2, 1), 1);
            let last = frame(&scene, 0, &last);
            let six = [first.clone(), borrowed, flipped, foreign, first, last];
            let formed = scene.owner.windows();
            inject_packed(&mut scene, 0, &six);
            get_tags();
            scene.polls(1);
            let tagged = get_tags();
            let formed = (
                scene.owner.windows().prepared - formed.prepared,
                scene.owner.windows().gets - formed.gets,
            );
            let after = scene.owner.report();
            assert_eq!(
                moved(datagrams_of(&before), datagrams_of(&after)),
                (1, 1, 0)
            );
            assert_eq!(after.dropped_by, before.dropped_by);
            assert_eq!(moved(frames(&before), frames(&after)), (2, 1, 4));
            assert_eq!(
                after.packed_dropped_by[DropReason::Unauthenticated as usize],
                3,
                "capacity {capacity}"
            );
            assert_eq!(after.packed_dropped_by[DropReason::Session as usize], 1);
            assert_eq!(submitted(&scene.control) - reads, 2, "capacity {capacity}");
            assert_eq!(scene.owner.census().live(), 2, "capacity {capacity}");
            assert_eq!(scene.owner.serve_report().requests, 2);
            // The reads are the two hits': the frame with the borrowed tag names request slot 1.
            scene.turns(4);
            let replies = scene.sent(0);
            let mut started: Vec<u64> = replies
                .iter()
                .filter(|sent| sent.kind == Kind::Start)
                .map(|sent| sent.request)
                .collect();
            started.sort_unstable();
            started.dedup();
            assert_eq!(
                started,
                [request(0, 1), request(2, 1)],
                "capacity {capacity}"
            );
            assert!(
                errors(&replies).is_empty(),
                "a refused frame draws no reply"
            );
            // The scan parses all six frames as GETs, so the windows hold them all: three windows of two, whose
            // boundaries fall inside the datagram, or one window of six.
            let expected = if capacity == 2 { (3, 6) } else { (1, 6) };
            assert_eq!(formed, expected, "capacity {capacity}");
            assert_eq!(
                tagged, 6,
                "each frame is tagged once, the refused ones too: capacity {capacity}"
            );
        });
    }
}

/// One datagram-level entry of a frame list, in receive order: the peers' entries arrive peer 0's first.
#[derive(Clone)]
enum Item {
    /// A sealed GET frame from the peer, which a partition may pack with the GET frames next to it.
    Get(usize, Vec<u8>),
    /// A datagram from the peer that stays alone in every partition.
    Lone(usize, Vec<u8>),
    /// A datagram on the peer's link that the transport reports as from no configured peer.
    Stranger(usize, Vec<u8>),
}

impl Item {
    /// The peer whose link carries the entry.
    fn peer(&self) -> usize {
        let (Item::Get(peer, _) | Item::Lone(peer, _) | Item::Stranger(peer, _)) = self;
        *peer
    }

    fn bytes(&self) -> &[u8] {
        let (Item::Get(_, bytes) | Item::Lone(_, bytes) | Item::Stranger(_, bytes)) = self;
        bytes
    }
}

/// One wire slot: its watermark, whether a request holds its binding, and the highest generation answered while one
/// did.
type Slot = (Option<u64>, bool, Option<u64>);

/// What one receive step leaves that is equal in every partition of its frame list into datagrams.
#[derive(Debug, PartialEq)]
struct Step {
    serve: super::serve::ServeReport,
    put: super::put::PutReport,
    sessions: super::session::SessionReport,
    census: super::requests::RequestCensus,
    /// The kind, request, status and sequence of each frame the owner sent to each peer in the step's poll, in send
    /// order.
    sent: [Vec<(Kind, u64, u16, u64)>; 2],
    get_frames: u64,
    /// Refused client traffic by reason: `dropped_by[r] + packed_dropped_by[r]`.
    refused: [u64; DropReason::COUNT],
    lookups: u64,
    /// Read commands the device accepted.
    reads: usize,
    /// Bare frames the step tagged in pairs, by receive slot.
    paired: usize,
    /// The owner's report after the step, with the counters that depend on the cut into datagrams zeroed: the
    /// datagram accounts, the frame accounts, the poll gaps and the receive pool's occupancy.
    owner: OwnerReport,
    /// Wire slots 0 to 3 of each peer after the step.
    slots: [[Slot; 4]; 2],
    /// The whole view of each of those slots as the owner's reader prints it: the bound request's handle and the
    /// retained row's session, expiry and outcome beside the fields of `slots`.
    views: [[String; 4]; 2],
}

/// Datagrams one receive call of the scene's owner takes from each of its two peers, under a batch of eight.
const SHARE: usize = 4;

/// The partitions of `items` into datagrams: each joins or separates every two adjacent GET frames of one peer, and
/// none packs more than [`MAX_PACKED_GETS`] frames or gives one peer more than [`SHARE`] datagrams. A partition lists
/// its datagrams as ranges of `items`; the first packs the fewest frames, and is the all-lone partition when that
/// one fits. The helper takes a list with at most 15 pairs of adjacent GET frames of one peer.
fn partitions(items: &[Item]) -> Vec<Vec<std::ops::Range<usize>>> {
    let joinable: Vec<usize> = (1..items.len())
        .filter(|&at| match (&items[at - 1], &items[at]) {
            (Item::Get(a, _), Item::Get(b, _)) => a == b,
            _ => false,
        })
        .collect();
    assert!(joinable.len() < 16, "one mask per partition");
    (0..1u32 << joinable.len())
        .filter_map(|mask| {
            let mut datagrams: Vec<std::ops::Range<usize>> = Vec::new();
            for at in 0..items.len() {
                let joined = joinable
                    .iter()
                    .position(|&joint| joint == at)
                    .is_some_and(|bit| mask >> bit & 1 == 1);
                match datagrams.last_mut() {
                    Some(last) if joined => last.end = at + 1,
                    _ => datagrams.push(at..at + 1),
                }
            }
            // One receive call takes at most `SHARE` datagrams from each peer.
            let fits = [0, 1].iter().all(|peer| {
                let from =
                    |datagram: &&std::ops::Range<usize>| items[datagram.start].peer() == *peer;
                datagrams.iter().filter(from).count() <= SHARE
            });
            (fits
                && datagrams
                    .iter()
                    .all(|datagram| datagram.len() <= MAX_PACKED_GETS))
            .then_some(datagrams)
        })
        .collect()
}

/// One run of [`step`].
struct Ran {
    /// What the step left.
    outcome: Step,
    /// Datagrams the frame list was cut into.
    datagrams: usize,
    /// What the step added to `get_frames`, to `get_datagrams` and to the total of `packed_dropped_by`.
    frame_accounts: (u64, u64, u64),
    /// Partitions the frame list has.
    partitions: usize,
}

/// Builds a fresh owner under `config`, runs `prepare` on it, injects the frame list `prepare` returns cut into the
/// datagrams `cut` picks from its partitions, and polls once. The poll's one receive call takes every datagram of
/// the list, which the step asserts from the received count. With `lone`, the step asserts that the list's first
/// partition cuts it into one datagram an item, and that this partition moves no packed frame drop.
fn step(
    config: OwnerConfig,
    prepare: &dyn Fn(&mut Scene<'_, '_>) -> Vec<Item>,
    cut: usize,
    lone: bool,
) -> Ran {
    let mut outcome = None;
    scene_over(storage_windowed(8, 8), config, &PRINCIPALS, |mut scene| {
        let items = prepare(&mut scene);
        let all = partitions(&items);
        assert!(
            !lone || all[0].len() == items.len(),
            "premise: partition 0 is all lone, one datagram an item"
        );
        let datagrams = &all[cut];
        scene.sent(0);
        scene.sent(1);
        let before = scene.owner.report();
        for (position, datagram) in datagrams.iter().enumerate() {
            let bytes: Vec<u8> = items[datagram.clone()]
                .iter()
                .flat_map(|item| item.bytes().iter().copied())
                .collect();
            let peer = items[datagram.start].peer();
            scene.nets[peer].borrow_mut().inject(1, &bytes);
            if matches!(items[datagram.start], Item::Stranger(..)) {
                RELABEL.with(|relabels| relabels.borrow_mut().push((position, Relabel::Stranger)));
            }
        }
        super::owner::PAIRED_BARE.with(|count| count.set(0));
        let (lookups, reads) = (scene.owner.lookups(), submitted(&scene.control));
        scene.polls(1);
        let after = scene.owner.report();
        assert_eq!(
            after.received - before.received,
            datagrams.len() as u64,
            "one receive call takes the whole list"
        );
        assert_eq!(super::attribution_tests::accounted(&after), None);
        assert_eq!(
            after.retained.packets, before.retained.packets,
            "the receive pool took back every datagram's lease"
        );
        if lone && cut == 0 {
            assert_eq!(
                after.packed_dropped_by, before.packed_dropped_by,
                "the all-lone partition packs nothing"
            );
        }
        assert_eq!(scene.owner.held_receive_leases(), 0);
        assert!(scene.owner.preparation_is_empty());
        let refused = std::array::from_fn(|reason| {
            after.dropped_by[reason] - before.dropped_by[reason] + after.packed_dropped_by[reason]
                - before.packed_dropped_by[reason]
        });
        let step = Step {
            serve: scene.owner.serve_report(),
            put: scene.owner.put_report(),
            sessions: scene.owner.session_report(),
            census: scene.owner.census(),
            sent: [0, 1].map(|peer| {
                let sent = scene.sent(peer);
                let brief =
                    |frame: &Header| (frame.kind, frame.request, frame.status, frame.sequence);
                sent.iter().map(brief).collect()
            }),
            get_frames: after.get_frames - before.get_frames,
            refused,
            lookups: scene.owner.lookups() - lookups,
            reads: submitted(&scene.control) - reads,
            paired: super::owner::PAIRED_BARE.with(std::cell::Cell::get),
            owner: OwnerReport {
                received: 0,
                handled: 0,
                dropped: 0,
                dropped_by: [0; DropReason::COUNT],
                get_frames: 0,
                get_datagrams: 0,
                packed_dropped_by: [0; DropReason::COUNT],
                poll_gap_max_us: 0,
                poll_gap_max_after: Default::default(),
                poll_gaps: Default::default(),
                retained: RetainedCensus {
                    packets: 0,
                    ..after.retained
                },
                ..after
            },
            views: [0, 1].map(|peer| {
                [0, 1, 2, 3]
                    .map(|slot| format!("{:?}", scene.owner.request_slot(PeerId(peer), slot)))
            }),
            slots: [0, 1].map(|peer| {
                [0, 1, 2, 3].map(|slot| {
                    let slot = scene.owner.request_slot(PeerId(peer), slot);
                    slot.map_or((None, false, None), |slot| {
                        (slot.watermark, slot.active.is_some(), slot.refused)
                    })
                })
            }),
        };
        outcome = Some(Ran {
            outcome: step,
            datagrams: datagrams.len(),
            frame_accounts: moved(frames(&before), frames(&after)),
            partitions: all.len(),
        });
    });
    outcome.expect("the scene ran")
}

/// Runs the frame list of `prepare` in every partition into datagrams and asserts each leaves the outcome the
/// all-lone partition leaves, in fewer datagrams. Returns the all-lone outcome and the partition count.
fn equal_in_every_partition(
    config: OwnerConfig,
    prepare: &dyn Fn(&mut Scene<'_, '_>) -> Vec<Item>,
) -> (Step, usize) {
    let lone = step(config, prepare, 0, true);
    let count = lone.partitions;
    for cut in 1..count {
        let packed = step(config, prepare, cut, true);
        assert_eq!(packed.outcome, lone.outcome, "partition {cut} of {count}");
        assert!(packed.datagrams < lone.datagrams, "partition {cut} packs");
    }
    (lone.outcome, count)
}

/// The statuses of the ERROR frames among `sent`, by request, in send order.
fn refusals(step: &Step, peer: usize) -> Vec<(u64, Status)> {
    step.sent[peer]
        .iter()
        .filter(|(kind, ..)| *kind == Kind::Error)
        .map(|(_, request, status, _)| (*request, Status::from_wire(*status).unwrap()))
        .collect()
}

/// A GET frame of key `name` from `peer` for `request` under the session's next sequence, as a list item.
fn get(scene: &mut Scene<'_, '_>, peer: usize, request: u64, name: u8) -> Item {
    let get = scene.get(peer, request, name);
    Item::Get(peer, frame(scene, peer, &get))
}

/// A peer whose share is full is refused `RequestPressure` for its next GET however the frames are cut into
/// datagrams: of four hits under a share of three, the fourth is refused and three reads start. Admission charged
/// once for a datagram would admit the fourth hit when it shares a datagram with an admitted one.
#[test]
fn a_get_past_its_peers_share_is_refused_in_every_partition() {
    let share = OwnerConfig {
        peer_requests: 3,
        ..config(8)
    };
    let (lone, count) = equal_in_every_partition(share, &|scene| {
        (0..4)
            .map(|slot| get(scene, 0, request(slot, 1), 1))
            .collect()
    });
    assert_eq!(count, 8);
    assert_eq!(
        refusals(&lone, 0),
        [(request(3, 1), Status::RequestPressure)]
    );
    assert_eq!(lone.serve.refused_pressure.peer, 1);
    assert_eq!((lone.get_frames, lone.lookups, lone.reads), (4, 3, 3));
    assert_eq!(lone.census.active, share.peer_requests);
}

/// A full request table refuses the next GET `RequestPressure` in every partition. The table of four slots holds one
/// retired slot and two reads of peer 1. Peer 0 sends three hits under generation 3, above every generation its
/// client's earlier requests gave those wire slots: the first takes the table's last slot and reads, and the second
/// and the third are refused at the full table.
#[test]
fn a_get_past_a_full_table_is_refused_in_every_partition() {
    let table = OwnerConfig {
        request_slots: 4,
        peer_requests: 2,
        ..config(8)
    };
    let (lone, count) = equal_in_every_partition(table, &|scene| {
        scene
            .owner
            .start_request_slot_at(0, super::requests::GENERATION_LIMIT);
        assert_eq!(scene.read(0, 1, 0).0, Some(super::fetch::Outcome::Complete));
        assert_eq!(scene.owner.census().retired, 1);
        scene.refresh(0);
        for slot in 0..2 {
            let held = scene.get(1, request(slot, 1), 1);
            scene.inject(1, &held);
        }
        scene.polls(1);
        assert_eq!(scene.owner.census().live(), 2);
        (1..4)
            .map(|slot| get(scene, 0, request(slot, 3), 1))
            .collect()
    });
    assert_eq!(count, 4);
    assert_eq!(
        refusals(&lone, 0),
        [
            (request(2, 3), Status::RequestPressure),
            (request(3, 3), Status::RequestPressure)
        ]
    );
    assert_eq!(lone.serve.refused_pressure.table, 2);
    assert_eq!(lone.get_frames, 3);
    assert_eq!(
        lone.census.live() + lone.census.retired,
        table.request_slots,
        "the table is full"
    );
    assert_eq!((lone.census.retired, lone.reads), (1, 1));
}

/// The frames of the busy wire slot list: a hit at slot 0, a hit at the same slot under the next generation, and a
/// hit at slot 1, with the first two in the order `order` gives.
fn busy_slot(order: [u64; 2]) -> impl Fn(&mut Scene<'_, '_>) -> Vec<Item> {
    move |scene| {
        let mut items = vec![
            get(scene, 0, request(0, 1), 1),
            get(scene, 0, request(0, 2), 1),
            get(scene, 0, request(1, 1), 1),
        ];
        if order == [2, 1] {
            items.swap(0, 1);
        }
        items
    }
}

/// A GET for a wire slot whose earlier generation is live is refused `RequestPressure` in every partition, and the
/// earlier generation keeps its read. The control swaps the two frames of that slot: the outcome differs, so the
/// comparison tells frame orders apart.
#[test]
fn a_get_for_a_busy_wire_slot_is_refused_in_every_partition() {
    let (lone, count) = equal_in_every_partition(config(8), &busy_slot([1, 2]));
    assert_eq!(count, 4);
    assert_eq!(
        refusals(&lone, 0),
        [(request(0, 2), Status::RequestPressure)]
    );
    assert_eq!(lone.serve.refused_pressure.busy, 1);
    assert_eq!((lone.get_frames, lone.reads), (3, 2));
    let (swapped, _) = equal_in_every_partition(config(8), &busy_slot([2, 1]));
    assert_ne!(swapped, lone, "two swapped frames leave another outcome");
    assert!(refusals(&swapped, 0).is_empty());
}

/// GETs beside saturated PUT caps: peer 0 holds its one PUT, a second PUT BEGIN is refused `RequestPressure` at the
/// peer's PUT cap, and three hits start their reads inside the peer's share of four, in every partition.
#[test]
fn gets_beside_saturated_put_caps_start_in_every_partition() {
    let (lone, count) = equal_in_every_partition(config(8), &|scene| {
        scene.begin(0, request(3, 1), 6);
        let begin = scene.frame(0, Kind::PutBegin, request(2, 1), 7, |_| {});
        let mut items = vec![Item::Lone(0, scene.sealed(0, &begin, &[], |_| {}))];
        items
            .extend([(0, 1), (1, 1), (2, 2)].map(|(slot, at)| get(scene, 0, request(slot, at), 1)));
        items
    });
    assert_eq!(count, 4);
    assert_eq!(config(8).put.peer_puts, 1);
    assert_eq!(lone.put.refused_peer_share, 1);
    let pressure = Status::RequestPressure as u16;
    assert_eq!(
        lone.sent[0],
        [(Kind::PutError, request(2, 1), pressure, 2)],
        "the refused BEGIN's reply"
    );
    assert_eq!((lone.get_frames, lone.reads), (3, 3));
    assert_eq!(lone.census.active, config(8).peer_requests);
}

/// GETs beside a saturated global PUT cap: each peer holds one PUT, which fills the owner's two PUTs, a further PUT
/// BEGIN from peer 0 is refused `RequestPressure` at the global cap, which the PUT core checks ahead of the peer's,
/// and three hits start their reads inside the peer's share of four, in every partition.
#[test]
fn gets_beside_a_saturated_global_put_cap_start_in_every_partition() {
    let (lone, count) = equal_in_every_partition(config(8), &|scene| {
        scene.begin(0, request(3, 1), 6);
        scene.begin(1, request(3, 1), 8);
        assert_eq!(
            scene.owner.put_occupancy().live,
            config(8).put.puts,
            "premise: the live PUTs fill the global cap"
        );
        let begin = scene.frame(0, Kind::PutBegin, request(2, 1), 7, |_| {});
        let mut items = vec![Item::Lone(0, scene.sealed(0, &begin, &[], |_| {}))];
        items
            .extend([(0, 1), (1, 1), (2, 2)].map(|(slot, at)| get(scene, 0, request(slot, at), 1)));
        items
    });
    assert_eq!(count, 4);
    assert_eq!(
        (lone.put.refused_global_cap, lone.put.refused_peer_share),
        (1, 0)
    );
    let pressure = Status::RequestPressure as u16;
    assert_eq!(
        lone.sent[0],
        [(Kind::PutError, request(2, 1), pressure, 2)],
        "the refused BEGIN's reply"
    );
    assert_eq!((lone.get_frames, lone.reads), (3, 3));
}

/// A reply ring of two entries meets one hit and three GETs for its busy wire slot: the three are refused
/// `RequestPressure`, the ring takes the first two refusals and the third reply is dropped and counted, in every
/// partition, a datagram of all four frames among them.
#[test]
fn a_reply_ring_smaller_than_the_datagram_drops_the_excess_replies_in_every_partition() {
    let ring = OwnerConfig {
        serve: super::serve::ServeConfig {
            replies: 2,
            ..config(8).serve
        },
        ..config(8)
    };
    let (lone, count) = equal_in_every_partition(ring, &|scene| {
        (1..5).map(|at| get(scene, 0, request(0, at), 1)).collect()
    });
    assert_eq!(count, 8);
    assert_eq!(
        refusals(&lone, 0),
        [
            (request(0, 2), Status::RequestPressure),
            (request(0, 3), Status::RequestPressure)
        ]
    );
    assert_eq!(lone.serve.refused_pressure.busy, 3);
    assert_eq!(
        (lone.serve.dropped_replies, lone.serve.reply_high_water),
        (1, 2)
    );
    assert_eq!((lone.get_frames, lone.reads), (4, 1));
    // Generation 1 holds the wire slot, and the slot records generation 4 as answered although its reply was
    // dropped: every refused identity stays settled.
    assert_eq!(lone.slots[0][0], (Some(1), true, Some(4)));
}

/// Mechanisms indexed by receive slot keep their work between packed datagrams, beside a refusal inside each. Each
/// peer's two hits name one wire slot under two generations, so the second meets a busy slot. Peer 0 sends its two
/// hits and two ACKs; peer 1 sends a WHO HOLDS, a PROBE and its two hits. In every partition the two ACKs are tagged
/// as one pair, the first question is answered with a HOLDER and the second is declined behind it, each peer's
/// first hit starts its read and its second is refused `RequestPressure`.
#[test]
fn an_ack_pair_and_two_questions_between_packed_datagrams_keep_their_handling() {
    use super::owner::tests::{query_body, session_header, token};
    let (lone, count) = equal_in_every_partition(config(8), &|scene| {
        let mut items: Vec<Item> = (1..3).map(|at| get(scene, 0, request(0, at), 1)).collect();
        for slot in 2..4 {
            let ack = ack(scene, 0, request(slot, 1));
            items.push(Item::Lone(0, scene.sealed(0, &ack, &[], |_| {})));
        }
        for kind in [Kind::WhoHolds, Kind::Probe] {
            let body = query_body(kind, token(scene).shard, None);
            let header = session_header(scene, 1, kind, body.len());
            items.push(Item::Lone(1, scene.sealed(1, &header, &body, |_| {})));
        }
        items.extend((1..3).map(|at| get(scene, 1, request(0, at), 1)));
        items
    });
    assert_eq!(count, 4);
    assert_eq!(lone.paired, 2);
    assert_eq!(lone.serve.stale_acks, 2);
    let pressure = Status::RequestPressure as u16;
    assert_eq!(lone.sent[0], [(Kind::Error, request(0, 2), pressure, 1)]);
    assert_eq!(
        lone.sent[1],
        [
            (Kind::Holder, 0, 0, 2),
            (Kind::Error, request(0, 2), pressure, 1)
        ],
        "the HOLDER carries the question's sequence and leaves ahead of the refusal"
    );
    assert_eq!(lone.serve.refused_pressure.busy, 2);
    let mut refused = [0; DropReason::COUNT];
    refused[DropReason::Declined as usize] = 1;
    assert_eq!(lone.refused, refused);
    assert_eq!((lone.get_frames, lone.reads), (4, 2));
}

/// A pending PUT DATA group and a stranger's datagram between packed datagrams: peer 0 sends two hits; peer 1 sends
/// a PUT DATA fragment that names no upload, a datagram the transport reports as from no configured peer, and two
/// hits. In every partition the fragment waits in its group across the stranger's datagram and the two hits after
/// it, to the end of the receive, and is declined by the PUT core; the stranger's datagram is one `NoPeer` drop; and
/// all four hits start their reads.
#[test]
fn a_pending_put_data_group_and_a_stranger_between_packed_datagrams_keep_their_handling() {
    let (lone, count) = equal_in_every_partition(config(8), &|scene| {
        let mut items: Vec<Item> = (0..2)
            .map(|slot| get(scene, 0, request(slot, 1), 1))
            .collect();
        let (header, body) = scene.fragment(request(3, 1), 7, &[0x3C; 100], 0);
        let strange = scene.get(1, request(2, 1), 1);
        let hits = [0, 1].map(|slot| scene.get(1, request(slot, 1), 1));
        // A group taken at the stranger's datagram would admit the fragment first and leave both hits outside
        // the replay window.
        let header = Header {
            sequence: hits[1].sequence + 128,
            ..header
        };
        items.push(Item::Lone(1, scene.sealed(1, &header, &body, |_| {})));
        items.push(Item::Stranger(1, frame(scene, 1, &strange)));
        items.extend(hits.map(|hit| Item::Get(1, frame(scene, 1, &hit))));
        items
    });
    assert_eq!(count, 4);
    assert_eq!(lone.sessions.stale, 0);
    let mut refused = [0; DropReason::COUNT];
    refused[DropReason::Declined as usize] = 1;
    refused[DropReason::NoPeer as usize] = 1;
    assert_eq!(lone.refused, refused);
    assert_eq!((lone.get_frames, lone.reads), (4, 4));
}

/// The frames of the replay window list from peer 1: a PUT DATA fragment at sequence `d` and GETs at `d + 127` and
/// `d + 128`, the fragment first or last.
fn across_the_window(fragment_first: bool) -> impl Fn(&mut Scene<'_, '_>) -> Vec<Item> {
    move |scene| {
        let (header, body) = scene.fragment(request(3, 1), 7, &[0x3C; 100], 0);
        let mut items = vec![Item::Lone(1, scene.sealed(1, &header, &body, |_| {}))];
        for (slot, ahead) in [(0, 127), (1, 128)] {
            let get = Header {
                sequence: header.sequence + ahead,
                ..scene.get(1, request(slot, 1), 1)
            };
            items.push(Item::Get(1, frame(scene, 1, &get)));
        }
        if !fragment_first {
            items.rotate_left(1);
        }
        items
    }
}

/// The check that takes a pending PUT DATA group before a frame that would age it out runs before each frame with
/// that frame's own sequence. Under the session's replay window of 128 sequences, a fragment at sequence `d` waits
/// in its group while GETs at `d + 127` and `d + 128` follow it: the first leaves the fragment inside the window,
/// and the group is taken before the second, so the session admits the fragment and counts nothing stale, in every
/// partition. A check that read a packed datagram's first sequence would admit both GETs first and refuse the
/// fragment as stale. The control delivers the fragment after both GETs, where the session refuses it as stale:
/// the window is 128 sequences wide.
#[test]
fn a_pending_fragment_is_taken_before_the_frame_that_would_age_it_out() {
    let (lone, count) = equal_in_every_partition(config(8), &across_the_window(true));
    assert_eq!(count, 2);
    assert_eq!(lone.sessions.stale, 0);
    let mut refused = [0; DropReason::COUNT];
    refused[DropReason::Declined as usize] = 1;
    assert_eq!(
        lone.refused, refused,
        "the PUT core declines the admitted fragment"
    );
    assert_eq!((lone.get_frames, lone.reads), (2, 2));
    let (late, _) = equal_in_every_partition(config(8), &across_the_window(false));
    assert_eq!(late.sessions.stale, 1);
    assert_eq!(late.refused[DropReason::Session as usize], 1);
}

/// A pending PUT DATA group waits for the frames behind it when none of them ages it out. Peer 1 sends a fragment
/// whose sequence is 128 above the second of the two GETs behind it. The fragment waits in its group while both
/// GETs are admitted and is taken at the end of the receive, so the session counts nothing stale and both hits
/// start their reads, in every partition. A group taken before the GETs would admit the fragment first and leave
/// both GETs outside the replay window of 128 sequences.
#[test]
fn a_pending_fragment_waits_for_the_frames_that_do_not_age_it_out() {
    let (lone, count) = equal_in_every_partition(config(8), &|scene| {
        let gets = [0, 1].map(|slot| scene.get(1, request(slot, 1), 1));
        let (header, body) = scene.fragment(request(3, 1), 7, &[0x3C; 100], 0);
        let header = Header {
            sequence: gets[1].sequence + 128,
            ..header
        };
        assert!(header.sequence - gets[0].sequence >= 128);
        let mut items = vec![Item::Lone(1, scene.sealed(1, &header, &body, |_| {}))];
        items.extend(gets.map(|get| Item::Get(1, frame(scene, 1, &get))));
        items
    });
    assert_eq!(count, 2);
    assert_eq!(lone.sessions.stale, 0);
    let mut refused = [0; DropReason::COUNT];
    refused[DropReason::Declined as usize] = 1;
    assert_eq!(
        lone.refused, refused,
        "the PUT core declines the admitted fragment"
    );
    assert_eq!((lone.get_frames, lone.reads), (2, 2));
}

/// A pending PUT DATA group is taken between the two frames of a packed datagram when only the second ages it out.
/// Peer 1 sends a fragment at sequence `g + 128`, then GETs at `g` and `g + 256`. The first GET leaves the fragment
/// inside the replay window of 128 sequences and is admitted; the group is taken before the second, so the session
/// admits all three and counts nothing stale, in every partition. A group taken when the datagram starts would
/// leave the first GET stale, and one taken after the datagram would leave the fragment stale.
#[test]
fn a_pending_fragment_is_taken_between_the_frames_of_a_packed_datagram() {
    let (lone, count) = equal_in_every_partition(config(8), &|scene| {
        let first = scene.get(1, request(0, 1), 1);
        let (header, body) = scene.fragment(request(3, 1), 7, &[0x3C; 100], 0);
        let header = Header {
            sequence: first.sequence + 128,
            ..header
        };
        let second = Header {
            sequence: first.sequence + 256,
            ..scene.get(1, request(1, 1), 1)
        };
        let mut items = vec![Item::Lone(1, scene.sealed(1, &header, &body, |_| {}))];
        items.extend([first, second].map(|get| Item::Get(1, frame(scene, 1, &get))));
        items
    });
    assert_eq!(count, 2);
    assert_eq!(lone.sessions.stale, 0);
    let mut refused = [0; DropReason::COUNT];
    refused[DropReason::Declined as usize] = 1;
    assert_eq!(
        lone.refused, refused,
        "the PUT core declines the admitted fragment"
    );
    assert_eq!((lone.get_frames, lone.reads), (2, 2));
}

/// A CANCEL for request `r` ahead of GETs for `r` and `q` leaves `r` without a read and starts `q`'s, whether the two
/// GETs share a datagram or not.
#[test]
fn a_cancel_ahead_of_its_get_leaves_that_request_without_a_read() {
    let (lone, count) = equal_in_every_partition(config(8), &|scene| {
        let cancel = super::window_tests::cancel_frame(scene, 0, request(0, 1));
        vec![
            Item::Lone(0, scene.sealed(0, &cancel, &[], |_| {})),
            get(scene, 0, request(0, 1), 1),
            get(scene, 0, request(1, 1), 1),
        ]
    });
    assert_eq!(count, 2);
    assert_eq!(
        (lone.serve.requests, lone.lookups, lone.reads),
        (1, 1, 1),
        "only the request the CANCEL did not name reads"
    );
    assert_eq!(lone.get_frames, 2);
    assert_eq!(lone.census.live(), 1);
    // The cancelled request's wire slot is settled at its generation and unbound, and the other is bound.
    assert_eq!(lone.slots[0][0], (Some(1), false, None));
    assert_eq!(lone.slots[0][1], (Some(1), true, None));
}

/// A GET for request `r` ahead of a second GET for `r` under a fresh sequence and a GET for `q`: two requests, one
/// duplicate and two reads in every partition, the lone GET ahead of its packed copy among them. Frames after a
/// datagram's first that skipped the namespace's routing would start a third read.
#[test]
fn a_get_ahead_of_its_copy_is_one_request_in_every_partition() {
    let (lone, count) = equal_in_every_partition(config(8), &|scene| {
        vec![
            get(scene, 0, request(0, 1), 1),
            get(scene, 0, request(0, 1), 1),
            get(scene, 0, request(1, 1), 1),
        ]
    });
    assert_eq!(count, 4);
    assert_eq!(
        (lone.serve.requests, lone.serve.duplicates, lone.reads),
        (2, 1, 2)
    );
    assert_eq!((lone.get_frames, lone.sessions.duplicate), (3, 0));
}

/// The frames of a straddling list from peer 0: after the session admitted sequence `s + 131`, `count` GETs at
/// sequences `s + first` up, naming wire slots 0 up under generation 2. Under a replay window of 128 the frames
/// below `s + 4` are stale, and they name a key the owner does not hold; the frames from `s + 4` on name a key it
/// holds. A stale frame that reached the serve core would draw a `Missing` reply and start no read.
fn straddling(first: u64, count: u16) -> impl Fn(&mut Scene<'_, '_>) -> Vec<Item> {
    move |scene| {
        let base = scene.get(0, request(0, 1), 1).sequence + 1;
        let newest = Header {
            sequence: base + 131,
            ..super::window_tests::cancel_frame(scene, 0, request(3, 1))
        };
        scene.inject(0, &newest);
        scene.polls(1);
        assert_eq!(scene.owner.session_report().stale, 0);
        (0..count)
            .map(|n| {
                let at = first + u64::from(n);
                let get = Header {
                    sequence: base + at,
                    ..scene.get(0, request(n % 4, 2), if at < 4 { 9 } else { 1 })
                };
                Item::Get(0, frame(scene, 0, &get))
            })
            .collect()
    }
}

/// Four frames at sequences `s + 2` to `s + 5` arrive after the session admitted `s + 131`, under a replay window of
/// 128: the first two are refused as stale and the last two start their reads, in every partition, with the four
/// lone datagrams as the reference.
#[test]
fn four_frames_that_straddle_the_replay_window_equal_their_lone_delivery() {
    let (lone, count) = equal_in_every_partition(config(8), &straddling(2, 4));
    assert_eq!(count, 8);
    assert_eq!(lone.sessions.stale, 2);
    assert_eq!(lone.refused[DropReason::Session as usize], 2);
    assert_eq!((lone.get_frames, lone.reads), (2, 2));
    assert!(refusals(&lone, 0).is_empty(), "no stale frame was served");
}

/// Eight frames at sequences `s` to `s + 7` arrive after the session admitted sequence `s + 131`, under a replay
/// window of 128: the first four are refused as stale and the last four are admitted and start their reads. The
/// window is consulted for each frame, so a datagram that straddles its edge is cut there. Every partition of the
/// eight frames into at most four datagrams, the most one receive call takes from a peer, leaves that outcome; the
/// eight lone datagrams span two receive calls, so this list has no all-lone arm.
#[test]
fn frames_that_straddle_the_replay_window_are_cut_at_its_edge_in_every_partition() {
    let prepare = straddling(0, 8);
    let ran = step(config(8), &prepare, 0, false);
    let (first, count) = (ran.outcome, ran.partitions);
    assert_eq!(
        count,
        1 + 7 + 21 + 35,
        "eight frames cut into one to four datagrams"
    );
    assert_eq!(ran.datagrams, SHARE);
    assert_eq!(first.sessions.stale, 4);
    assert_eq!(first.refused[DropReason::Session as usize], 4);
    assert_eq!(first.reads, 4);
    // The first partition packs the first five frames and leaves the last three alone. The packed datagram's
    // first four frames are stale and its fifth is served, so it counts among the four datagrams that carried a
    // GET frame.
    assert_eq!(ran.frame_accounts, (4, 4, 4));
    assert!(refusals(&first, 0).is_empty(), "no stale frame was served");
    for cut in 1..count {
        let packed = step(config(8), &prepare, cut, false);
        assert_eq!(packed.outcome, first, "partition {cut} of {count}");
    }
}

/// One poll handles `batch` packed datagrams of eight frames: eight datagrams, four from each peer, raise
/// `get_frames` by 64 in the receiving poll. Each datagram names its peer's four wire slots twice, under two
/// successive generations, so a peer's four datagrams name each slot eight times. All 64 frames reach the serve
/// core, which admits four GETs within each peer's share of four and refuses the other 28 of each peer
/// `RequestPressure`; lookups stop at the two shares, and no receive lease stays held. Each peer's reply ring takes
/// as many refusals as it has entries and drops and counts the rest. The volume's read commands go to the first
/// hits in the receiving poll, and the hits behind them submit theirs on later polls.
#[test]
fn one_poll_handles_batch_packed_datagrams_of_eight_frames() {
    windowed(8, 8, |mut scene| {
        let batch = config(8).batch as usize;
        let (before, lookups) = (scene.owner.report(), scene.owner.lookups());
        let (serve, reads) = (scene.owner.serve_report(), submitted(&scene.control));
        let waited = scene.owner.volume_report().reads_waited;
        assert_eq!(
            serve.reply_high_water, 0,
            "premise: no reply was queued, so the rings start empty"
        );
        for peer in 0..2 {
            for datagram in 0..batch as u64 / 2 {
                let eight: Vec<Vec<u8>> = (0..MAX_PACKED_GETS as u16)
                    .map(|n| {
                        let at = 1 + 2 * datagram + u64::from(n / 4);
                        let get = scene.get(peer, request(n % 4, at), 1);
                        frame(&scene, peer, &get)
                    })
                    .collect();
                inject_packed(&mut scene, peer, &eight);
            }
        }
        scene.polls(1);
        let after = scene.owner.report();
        let all = (batch * MAX_PACKED_GETS) as u64;
        assert_eq!(all, 64);
        assert_eq!(
            moved(datagrams_of(&before), datagrams_of(&after)),
            (batch as u64, batch as u64, 0)
        );
        assert_eq!(
            moved(frames(&before), frames(&after)),
            (all, batch as u64, 0)
        );
        let shares = 2 * u64::from(config(8).peer_requests);
        assert_eq!(scene.owner.lookups() - lookups, shares);
        assert_eq!(u64::from(scene.owner.census().live()), shares);
        assert_eq!(scene.owner.held_receive_leases(), 0);
        assert!(scene.owner.preparation_is_empty());
        let served = scene.owner.serve_report();
        let pressure = &served.refused_pressure;
        let refused = pressure.peer + pressure.table + pressure.busy
            - serve.refused_pressure.peer
            - serve.refused_pressure.table
            - serve.refused_pressure.busy;
        assert_eq!(refused, all - shares);
        let rings = 2 * u64::from(config(8).serve.replies);
        assert!(refused > rings, "premise: the refusals exceed the rings");
        assert_eq!(
            served.dropped_replies - serve.dropped_replies,
            refused - rings
        );
        assert_eq!(served.reply_high_water, config(8).serve.replies);
        assert_eq!(after.retained.packets, before.retained.packets);
        assert_eq!(
            scene.owner.volume_report().reads_waited - waited,
            shares - super::window_tests::READ_COMMANDS as u64,
            "the hits past the volume's read commands wait in the receiving poll"
        );
        assert_eq!(
            submitted(&scene.control) - reads,
            super::window_tests::READ_COMMANDS,
            "the receiving poll submits a first command for as many hits as the volume has read commands"
        );
        scene.turns(40);
        assert!(
            submitted(&scene.control) - reads >= shares as usize,
            "the hits that waited for a read command submit theirs with no further GET"
        );
    });
}

/// A warm poll over a full packed datagram allocates nothing. Each round sends eight GET frames in one datagram,
/// four misses and four GETs for the same wire slots under the next generation, and counts the allocations of the
/// poll that receives it; the first round warms the owner, and the two rounds after it allocate nothing. Every round
/// prepares a window over the datagram and passes all eight frames to the serve core. The frames are misses, whose
/// requests end without a client, so each round starts from an empty table.
#[test]
fn a_warm_poll_over_a_full_packed_datagram_allocates_nothing() {
    windowed(8, 8, |mut scene| {
        let mut counted = Vec::new();
        for round in 0..3u64 {
            let built = crate::instrument::allocations();
            let eight: Vec<Vec<u8>> = (0..MAX_PACKED_GETS as u16)
                .map(|n| {
                    let at = 1 + 2 * round + u64::from(n / 4);
                    let get = scene.get(0, request(n % 4, at), 9);
                    frame(&scene, 0, &get)
                })
                .collect();
            assert!(
                crate::instrument::allocations() > built,
                "premise: the counter sees this thread's allocations"
            );
            inject_packed(&mut scene, 0, &eight);
            let (before, formed) = (scene.owner.report(), scene.owner.windows());
            for net in &scene.nets {
                net.borrow_mut().advance(scene.turn);
            }
            let allocations = crate::instrument::allocations();
            scene.owner.poll(scene.turn * 100);
            counted.push(crate::instrument::allocations() - allocations);
            scene.turn += 1;
            let after = scene.owner.report();
            assert_eq!(
                moved(frames(&before), frames(&after)),
                (8, 1, 0),
                "round {round}"
            );
            let windows = scene.owner.windows();
            assert_eq!(
                (
                    windows.prepared - formed.prepared,
                    windows.gets - formed.gets
                ),
                (1, 8),
                "one window holds the datagram's eight frames: round {round}"
            );
            // The round's requests end and leave their slots before the next round names them again.
            scene.turns(700);
            assert_eq!(scene.owner.census().live(), 0, "round {round}");
        }
        assert_eq!(counted[1..], [0, 0], "{counted:?}");
    });
}

/// A scripted history reads both frame counters and the datagram accounts after each datagram: a lone GET, a packed
/// datagram of three GETs, an ACK and an unparseable datagram. The lone GET and the packed datagram each count one
/// datagram that carried a GET frame, the ACK is handled without a GET frame, and the junk is one drop.
#[test]
fn a_scripted_history_predicts_the_frame_and_datagram_accounts() {
    windowed(8, 8, |mut scene| {
        let start = scene.owner.report();
        let read = |scene: &mut Scene<'_, '_>| {
            scene.polls(1);
            let now = scene.owner.report();
            let (get_frames, get_datagrams, refused) = moved(frames(&start), frames(&now));
            assert_eq!(refused, 0);
            (
                (get_frames, get_datagrams),
                moved(datagrams_of(&start), datagrams_of(&now)),
            )
        };
        let lone = scene.get(0, request(0, 1), 1);
        scene.inject(0, &lone);
        assert_eq!(read(&mut scene), ((1, 1), (1, 1, 0)));
        let three: Vec<Vec<u8>> = (1..4)
            .map(|slot| {
                let get = scene.get(0, request(slot, 1), 1);
                frame(&scene, 0, &get)
            })
            .collect();
        inject_packed(&mut scene, 0, &three);
        assert_eq!(read(&mut scene), ((4, 2), (2, 2, 0)));
        let ack = ack(&mut scene, 0, request(0, 9));
        scene.inject(0, &ack);
        assert_eq!(read(&mut scene), ((4, 2), (3, 3, 0)));
        scene.nets[0].borrow_mut().inject(1, &[0x5A; 64]);
        assert_eq!(read(&mut scene), ((4, 2), (4, 3, 1)));
        assert_eq!(
            super::attribution_tests::accounted(&scene.owner.report()),
            None
        );
    });
}

/// Five frames, a fresh GET `a`, a GET `b` sealed under another peer's key, `a` again, a GET `c` whose magic changed
/// before sealing, and a fresh GET `d`, move the accounts by frame when packed and by datagram when lone. Packed, the
/// one datagram is handled and no `dropped_by` entry moves; lone, two datagrams are handled and three dropped. For
/// every reason the lone `dropped_by` equals the packed `dropped_by + packed_dropped_by`, and both arms pass `a` and
/// `d` to the serve core.
#[test]
fn five_frames_move_the_same_reasons_packed_and_lone() {
    let arm = |packed: bool| {
        let mut report = None;
        windowed(8, 8, |mut scene| {
            let before = scene.owner.report();
            let a = scene.get(0, request(0, 1), 1);
            let a = frame(&scene, 0, &a);
            let b = scene.get(0, request(1, 1), 1);
            let b = frame(&scene, 1, &b);
            let c = scene.get(0, request(2, 1), 1);
            let c = scene.sealed(0, &c, &[], |encoded| encoded[0] ^= 1);
            let d = scene.get(0, request(3, 1), 1);
            let d = frame(&scene, 0, &d);
            let five = [a.clone(), b, a, c, d];
            if packed {
                inject_packed(&mut scene, 0, &five);
            } else {
                for lone in &five {
                    scene.nets[0].borrow_mut().inject(1, lone);
                }
            }
            // A receive takes four datagrams from one peer, so the five lone ones arrive over two polls.
            scene.polls(2);
            assert_eq!(scene.owner.serve_report().requests, 2);
            assert_eq!(before.dropped_by, [0; DropReason::COUNT]);
            assert_eq!(frames(&before), (0, 0, 0));
            report = Some((before, scene.owner.report()));
        });
        report.expect("the scene ran")
    };
    let ((before, packed), (start, lone)) = (arm(true), arm(false));
    assert_eq!(
        moved(datagrams_of(&before), datagrams_of(&packed)),
        (1, 1, 0)
    );
    assert_eq!(packed.dropped_by, [0; DropReason::COUNT]);
    assert_eq!(frames(&packed), (2, 1, 3));
    assert_eq!(moved(datagrams_of(&start), datagrams_of(&lone)), (5, 2, 3));
    assert_eq!(frames(&lone), (2, 2, 0));
    let mut expected = [0; DropReason::COUNT];
    expected[DropReason::Unauthenticated as usize] = 1;
    expected[DropReason::Session as usize] = 1;
    expected[DropReason::Malformed as usize] = 1;
    assert_eq!(lone.dropped_by, expected);
    assert_eq!(packed.packed_dropped_by, expected);
}

/// A copy of a handled packed datagram of three GETs moves `received` and `handled` by one and the packed frame
/// account by three under `Session`, and nothing else in the owner's report, the serve report or the census: the
/// session replay window refuses each frame as a duplicate before any request state reads it.
#[test]
fn a_copy_of_a_handled_packed_datagram_moves_only_its_accounts() {
    windowed(8, 8, |mut scene| {
        let three = gets(&mut scene, 0, 3, 1, 1);
        inject_packed(&mut scene, 0, &three);
        scene.polls(1);
        assert_eq!(
            scene.owner.report().get_frames,
            3,
            "the datagram was handled"
        );
        let (before, serve) = (scene.owner.report(), scene.owner.serve_report());
        let (sessions, census) = (scene.owner.session_report(), scene.owner.census());
        inject_packed(&mut scene, 0, &three);
        scene.polls(1);
        let after = scene.owner.report();
        let mut packed_dropped_by = before.packed_dropped_by;
        packed_dropped_by[DropReason::Session as usize] += 3;
        let expected = OwnerReport {
            received: before.received + 1,
            handled: before.handled + 1,
            packed_dropped_by,
            // A poll records the gap since the poll before it.
            poll_gaps: after.poll_gaps,
            poll_gap_max_us: after.poll_gap_max_us,
            poll_gap_max_after: after.poll_gap_max_after,
            ..before
        };
        assert_eq!(after, expected);
        assert_eq!(scene.owner.serve_report(), serve);
        assert_eq!(scene.owner.census(), census);
        let now = scene.owner.session_report();
        assert_eq!(now.duplicate - sessions.duplicate, 3);
        assert_eq!(
            super::session::SessionReport {
                duplicate: sessions.duplicate,
                ..now
            },
            sessions
        );
    });
}

/// What a copy of a handled datagram must leave unchanged: the serve report, the census, the lookups, the read
/// commands the device accepted and the datagrams the owner sent.
fn untouched(
    scene: &Scene<'_, '_>,
) -> (
    super::serve::ServeReport,
    super::requests::RequestCensus,
    u64,
    usize,
    u64,
) {
    (
        scene.owner.serve_report(),
        scene.owner.census(),
        scene.owner.lookups(),
        submitted(&scene.control),
        scene.owner.report().sent,
    )
}

/// A copy of a handled packed datagram [A, B] is refused frame by frame at session admission, by the replay window,
/// before any request state reads it. The datagram is the two GET frames a real client sent for A and B, joined by
/// hand; the client completes both. The copy arrives three times: after A's COMPLETE was sent and both requests left
/// the owner, where the window refuses each frame as a `Duplicate`; after a successor request holds A's wire slot,
/// `Duplicate` again; and after the session admitted a sequence 128 past the copy's, where the window refuses each
/// frame as `Stale`. Each copy moves the session counter and the packed frame account under `Session` by two and
/// leaves the serve report, the census, the lookups, the reads and the owner's sent count unchanged.
#[test]
fn a_copy_of_a_handled_packed_datagram_is_refused_frame_by_frame_at_session_admission() {
    use super::owner_tests::key;
    use crate::sim::round::Actor;
    windowed(8, 8, |mut scene| {
        let crc = crate::storage::Crc32c::detect();
        let now = scene.turn * 100;
        // Each poll hands out one GET, so each leaves in a datagram of its own.
        let ids = [0, 1].map(|_| {
            let id = scene.clients[0]
                .get(key(1), 0, 1 << 20, now, 30_000_000)
                .unwrap();
            scene.clients[0].poll(now);
            id
        });
        let mut pair = Vec::new();
        scene.nets[0].borrow_mut().retain(1, |bytes| {
            pair.push(bytes.to_vec());
            false
        });
        let sent: Vec<Header> = pair
            .iter()
            .map(|bytes| super::frame::parse(crc, bytes, false).unwrap().header())
            .collect();
        assert_eq!(
            sent.iter().map(|get| get.kind).collect::<Vec<_>>(),
            [Kind::Get, Kind::Get]
        );
        let [a, b] = [sent[0].request, sent[1].request];
        let newest = sent[1].sequence;
        let before = scene.owner.report();
        inject_packed(&mut scene, 0, &pair);
        let mut bytes = [0, 0];
        for _ in 0..4_000 {
            scene.turn_with(&mut [(Actor::Client(0), &mut |clients, _, now| {
                let _ = clients[0].poll(now);
            })]);
            for (id, bytes) in ids.iter().zip(&mut bytes) {
                while let Some(fragment) = scene.clients[0].take(*id) {
                    *bytes += fragment.bytes().len();
                }
            }
            let done = ids.iter().all(|id| scene.clients[0].outcome(*id).is_some());
            if done && scene.owner.census().live() == 0 {
                break;
            }
        }
        for id in ids {
            assert_eq!(
                scene.clients[0].outcome(id),
                Some(super::fetch::Outcome::Complete)
            );
        }
        assert_eq!(bytes, [1000, 1000]);
        let handled = scene.owner.report();
        assert_eq!(moved(frames(&before), frames(&handled)), (2, 1, 0));
        let serve = scene.owner.serve_report();
        assert_eq!((serve.requests, serve.completed), (2, 2));
        assert_eq!(scene.owner.census().live(), 0, "A's COMPLETE was sent");

        let session = DropReason::Session as usize;
        let copy = |scene: &mut Scene<'_, '_>, stale: bool| {
            scene.nets[0].borrow_mut().clear(0);
            let (kept, sessions) = (untouched(scene), scene.owner.session_report());
            let report = scene.owner.report();
            inject_packed(scene, 0, &pair);
            scene.polls(1);
            let after = scene.owner.report();
            assert_eq!(
                moved(datagrams_of(&report), datagrams_of(&after)),
                (1, 1, 0)
            );
            assert_eq!(moved(frames(&report), frames(&after)), (0, 0, 2));
            assert_eq!(
                after.packed_dropped_by[session] - report.packed_dropped_by[session],
                2
            );
            let now = scene.owner.session_report();
            assert_eq!(
                (
                    now.duplicate - sessions.duplicate,
                    now.stale - sessions.stale
                ),
                if stale { (0, 2) } else { (2, 0) }
            );
            assert_eq!(untouched(scene), kept);
            assert!(scene.sent(0).is_empty());
        };
        copy(&mut scene, false);

        // A successor takes A's wire slot under the next generation, and the owner admits it.
        assert!(scene.clients[0].retire(ids[0]));
        let now = scene.turn * 100;
        let successor = scene.clients[0]
            .get(key(1), 0, 1 << 20, now, 30_000_000)
            .unwrap();
        scene.clients[0].poll(now);
        let next = scene.nets[0].borrow().peek(1).expect("the successor's GET");
        let next = super::frame::parse(crc, &next, false).unwrap().header();
        assert_eq!(next.request >> 48, a >> 48, "A's wire slot");
        assert!(next.request > a, "a later generation");
        assert!(scene.clients[0].outcome(successor).is_none());
        scene.polls(1);
        assert_eq!(scene.owner.serve_report().requests, 3);
        assert_eq!(scene.owner.census().live(), 1, "the successor is live");
        copy(&mut scene, false);

        // A CANCEL of an idle slot carries a sequence 128 past the copy's second frame.
        let later = Header {
            sequence: newest + 128,
            ..super::window_tests::cancel_frame(&mut scene, 0, request(3, 1))
        };
        assert_ne!(b >> 48, 3);
        scene.inject(0, &later);
        scene.polls(1);
        copy(&mut scene, true);
        assert_eq!(
            scene.owner.census().live(),
            1,
            "the successor keeps its slot"
        );
    });
}
