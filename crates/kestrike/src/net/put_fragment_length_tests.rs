//! A PUT DATA fragment whose payload disagrees with the attempt's manifest is refused.
//!
//! The scenario takes the PUT DATA datagram of fragment 0 of a three-fragment upload, a fragment the
//! manifest gives 8192 bytes, and cuts one byte from its end. `resized` then repairs every field
//! derived from the body: the datagram length, the body checksum, the header checksum and the tag
//! under the sending peer's key. The cut datagram is canonical and authentic in every respect but
//! one: its payload is one byte shorter than the manifest's share for index 0.
//!
//! The first test checks the parser: `frame::parse` accepts the whole datagram and refuses the cut one
//! naming the datagram length of a PUT DATA frame. The second checks the owner's replies over a ready
//! upload: the cut fragment reaches the owner, is dropped and draws no PUT reply, the receipt base
//! stays at 0 while fragment 1 arrives, and the whole fragment 0 then moves the base to 2. The same
//! upload without the cut fragment gives the same PUT ACKs from fragment 1 on, and both publish the
//! object's bytes.
//!
//! Each test gathers what it saw inside the scene, lets the scene go, and asserts on the gathered
//! values.

use super::auth::KeyRing;
use super::datagram::{HEADER_LEN, PeerId};
use super::frame::{
    AUTHENTICATED_LEN, Direction, Field, FrameError, Header, Kind, MacInput, parse,
};
use super::frame_tests::{bitwise_crc32c, crc, reseal};
use super::geometry::FRAGMENT_LEN;
use super::owner_tests::{OWNER, PRINCIPALS, payload};
use super::put_tests::{Scene, ready_upload, scene};

/// The header offset of the datagram body length, a big-endian `u32`.
const DATAGRAM_LEN_AT: usize = 112;
/// The header offset of the body's crc32c, a big-endian `u32`.
const BODY_CRC_AT: usize = 164;
/// The bytes the scenario cuts from the fragment: the smallest disagreement with the manifest.
const CUT: usize = 1;
/// The peer that uploads; `Scene::fragment` builds its frames.
const PEER: usize = 1;
/// The key the upload publishes, the one `ready_upload` prepares.
const NAME: u8 = 5;

/// `datagram`, a PUT DATA datagram toward the owner tagged under `ring`, with its last `cut` body bytes
/// removed and every field derived from the body recomputed: the datagram length, the body crc, the
/// header crc and the tag. With `cut` 0 the result equals `datagram`.
fn resized(ring: &KeyRing, datagram: &[u8], cut: usize) -> Vec<u8> {
    let mut bytes = datagram[..datagram.len() - cut].to_vec();
    let len = (bytes.len() - HEADER_LEN) as u32;
    bytes[DATAGRAM_LEN_AT..DATAGRAM_LEN_AT + 4].copy_from_slice(&len.to_be_bytes());
    let body_crc = bitwise_crc32c(&bytes[HEADER_LEN..]);
    bytes[BODY_CRC_AT..BODY_CRC_AT + 4].copy_from_slice(&body_crc.to_be_bytes());
    reseal(&mut bytes);
    let (head, body) = bytes.split_at(HEADER_LEN);
    let input = MacInput {
        endpoint: OWNER.endpoint,
        direction: Direction::ClientToOwner,
        header: head[..AUTHENTICATED_LEN].try_into().unwrap(),
        body: [body, &[]],
    };
    let tag = ring.tag(PeerId(0), &input).unwrap();
    bytes[AUTHENTICATED_LEN..HEADER_LEN].copy_from_slice(&tag);
    bytes
}

/// The object of the scenario's upload: three whole fragments, so fragment 0 is not the last.
fn object() -> Vec<u8> {
    payload(3 * FRAGMENT_LEN as usize, 4107)
}

/// The sealed PUT DATA datagram of fragment `index` of `object`, under the peer's next sequence number.
fn whole(scene: &mut Scene<'_, '_>, at: u64, serial: u64, object: &[u8], index: u32) -> Vec<u8> {
    let (header, body) = scene.fragment(at, serial, object, index);
    scene.sealed(PEER, &header, &body, |_| {})
}

/// What `parse` makes of a datagram: the header it accepts, or its refusal.
fn parsed(datagram: &[u8]) -> Result<Header, FrameError> {
    parse(crc(), datagram, false).map(|frame| frame.header())
}

/// The cut fragment is refused at the parser, naming the datagram length of a PUT DATA frame, and the
/// whole datagram it was cut from parses with the manifest's 8192 bytes. Resizing by nothing returns
/// the whole datagram byte for byte, so the cut one differs from a sender's datagram only in its
/// length.
#[test]
fn a_put_data_fragment_one_byte_short_of_its_manifest_length_is_refused_at_the_parser() {
    let mut seen = None;
    scene(&PRINCIPALS, |mut scene| {
        let object = object();
        let (at, serial) = ready_upload(&mut scene, &object);
        let sent = whole(&mut scene, at, serial, &object, 0);
        let same = resized(&scene.rings[PEER], &sent, 0);
        let cut = resized(&scene.rings[PEER], &sent, CUT);
        seen = Some((
            same == sent,
            cut.len(),
            parsed(&sent).map(|header| (header.kind, header.index, header.datagram_len)),
            parsed(&cut).map(|header| (header.kind, header.index, header.datagram_len)),
        ));
    });
    let (same, cut_len, sent, cut) = seen.expect("the scene ran");
    assert!(same, "resizing by nothing changes no byte of the datagram");
    assert_eq!(cut_len, HEADER_LEN + FRAGMENT_LEN as usize - CUT);
    assert_eq!(
        sent,
        Ok((Kind::PutData, 0, FRAGMENT_LEN)),
        "the whole fragment parses"
    );
    assert_eq!(
        cut,
        Err(FrameError::Field {
            kind: Kind::PutData,
            field: Field::DatagramLen,
        }),
        "a payload shorter than the manifest's fragment length is refused, naming the length"
    );
}

/// What the owner did in one upload of the scenario.
#[derive(Debug, PartialEq, Eq)]
struct Upload {
    /// The owner's received and dropped datagram counts over the cut fragment's delivery, and the PUT
    /// replies it drew; `None` in the upload that sends no cut fragment.
    cut: Option<(u64, u64, Vec<Kind>)>,
    /// The PUT ACKs after fragment 1, after the whole fragment 0, and after fragment 2, each as
    /// (receipt base, receipt mask, grant).
    acks: [Vec<(u32, u64, u32)>; 3],
    /// Whether the owner answered the last fragment with PUT RESULT.
    published: bool,
    /// Whether a GET of the key returns the object's bytes.
    intact: bool,
}

/// The PUT replies the owner sent the uploading peer after `datagram` arrived.
fn deliver(scene: &mut Scene<'_, '_>, datagram: &[u8]) -> Vec<Header> {
    scene.nets[PEER].borrow_mut().inject(1, datagram);
    scene.turns(4);
    scene.replies(PEER)
}

fn acks(replies: &[Header]) -> Vec<(u32, u64, u32)> {
    replies
        .iter()
        .filter(|reply| reply.kind == Kind::PutAck)
        .map(|reply| (reply.index, reply.offset, reply.grant))
        .collect()
}

/// Uploads the object as fragments 1, 0, 2 over a ready upload, after the cut fragment 0 when `cut`.
/// When the cut fragment draws a PUT reply the upload stops there, with the later steps empty.
fn upload(cut: bool) -> Upload {
    let mut seen = None;
    scene(&PRINCIPALS, |mut scene| {
        let object = object();
        let (at, serial) = ready_upload(&mut scene, &object);
        let mut upload = Upload {
            cut: None,
            acks: [Vec::new(), Vec::new(), Vec::new()],
            published: false,
            intact: false,
        };
        if cut {
            let sent = whole(&mut scene, at, serial, &object, 0);
            let short = resized(&scene.rings[PEER], &sent, CUT);
            let before = scene.owner.report();
            let replies = deliver(&mut scene, &short);
            let after = scene.owner.report();
            let kinds: Vec<Kind> = replies.iter().map(|reply| reply.kind).collect();
            let answered = !kinds.is_empty();
            upload.cut = Some((
                after.received - before.received,
                after.dropped - before.dropped,
                kinds,
            ));
            if answered {
                seen = Some(upload);
                return;
            }
        }
        let mut last = Vec::new();
        for (step, index) in [1, 0, 2].into_iter().enumerate() {
            let datagram = whole(&mut scene, at, serial, &object, index);
            last = deliver(&mut scene, &datagram);
            upload.acks[step] = acks(&last);
        }
        scene.turns(10);
        last.extend(scene.replies(PEER));
        upload.published = last.iter().any(|reply| reply.kind == Kind::PutResult);
        upload.intact = upload.published && scene.fetch(NAME) == object;
        seen = Some(upload);
    });
    seen.expect("the scene ran")
}

/// The owner drops the cut fragment before its PUT core sees it: the datagram is received and
/// dropped, draws no PUT ACK or any other PUT reply, and the receipt base is still 0 when fragment 1
/// is acknowledged. The whole fragment 0 is then acknowledged with the base past both fragments, and
/// the upload publishes the object. From fragment 1 on the owner's PUT ACKs equal those of the same
/// upload without the cut fragment.
#[test]
fn the_owner_sends_no_put_ack_for_a_cut_fragment_and_keeps_its_receipt_base() {
    let (faulted, plain) = (upload(true), upload(false));
    assert_eq!(
        faulted.cut,
        Some((1, 1, Vec::new())),
        "(received, dropped, PUT replies) over the cut fragment"
    );
    let bases = |upload: &Upload| -> Vec<Option<u32>> {
        upload
            .acks
            .iter()
            .map(|acks| acks.last().map(|ack| ack.0))
            .collect()
    };
    assert_eq!(
        bases(&faulted),
        [Some(0), Some(2), Some(3)],
        "the receipt base after fragment 1, the whole fragment 0 and fragment 2: {faulted:?}"
    );
    assert_eq!(
        (faulted.published, faulted.intact),
        (true, true),
        "the upload publishes the object's bytes"
    );
    assert_eq!(plain.cut, None);
    assert_eq!(
        (&faulted.acks, faulted.published, faulted.intact),
        (&plain.acks, plain.published, plain.intact),
        "the cut fragment changed nothing the owner acknowledged"
    );
}
