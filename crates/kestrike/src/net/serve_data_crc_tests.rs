//! A DATA fragment's body crc is the crc32c of exactly the payload bytes it carries,
//! derived at staging from the chunks it spans.
//!
//! Each test drives a real `ServeCore` through one GET of a 20,000-byte object (1,000 metadata bytes and
//! 19,000 body bytes) delivered as two retained chunks, takes every frame one poll stages and, for each
//! DATA frame, compares its `body_crc` with `Crc32c::detect().checksum` over the object's bytes
//! `[offset, offset + datagram_len)`.
//!
//! - `a_fragment_spanning_two_chunks_carries_the_crc_of_its_bytes`: the chunks are 12,000 and 8,000
//!   bytes, so under the 8,192-byte fragment the middle fragment takes its bytes from both chunks and
//!   the first and last lie inside one chunk each.
//! - `fragments_inside_one_chunk_carry_the_crc_of_their_bytes`: the same object and steps with the
//!   chunk boundary on the fragment boundary (8,192 and 11,808 bytes), so no fragment spans two chunks.
//!
//! That each frame carries the object's bytes at its offset, and how many chunks it draws them from,
//! are premises: they are asserted under their own messages before the crc.

use crate::storage::{Crc32c, EngineBudget};

use super::frame::Kind;
use super::owner_tests::payload;
use super::requests::RequestTable;
use super::serve::{GetOutcome, Manifest, ReadEnd};
use super::serve_tests::{CONFIG, Core, get, session};
use super::served::Request;

type Chunk = Box<[u8]>;

const OBJECT_LEN: usize = 20_000;
const FRAGMENT: usize = 8_192;

fn object() -> Vec<u8> {
    payload(OBJECT_LEN, 47)
}

const MANIFEST: Manifest = Manifest {
    allocation: 7,
    metadata_len: 1_000,
    body_len: 19_000,
};

/// One DATA frame as the poll staged it, copied out of the core.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Staged {
    index: u32,
    offset: usize,
    len: usize,
    /// The payload pieces together.
    bytes: Vec<u8>,
    /// Nonempty payload pieces: the retained chunks the fragment draws from.
    pieces: usize,
    body_crc: u32,
}

/// Serves the object as two chunks split at `boundary` and returns every DATA frame one poll staged,
/// with the kinds of every frame of that poll. The core is dropped before this returns.
fn staged(boundary: usize) -> (Vec<Staged>, Vec<Kind>) {
    let table = RequestTable::<Request<Chunk>>::new(4, 2, 2);
    let mut core: Core<Chunk> =
        Core::new(CONFIG, table, 2, 128, 0, 4, &mut EngineBudget::new(1 << 20))
            .expect("a core within its engine budget");
    let request = get(1, 0, 8);
    let GetOutcome::Read { id, .. } = core.get(session(8), &request, 0) else {
        panic!("a new request starts a read");
    };
    core.read_started(id);
    let data = object();
    let first = core.chunk(
        id,
        MANIFEST,
        0..boundary as u64,
        data[..boundary].into(),
        &[],
        0,
    );
    if core.wants_grant(id) {
        core.granted(id);
    }
    let second = core.chunk(
        id,
        MANIFEST,
        boundary as u64..OBJECT_LEN as u64,
        data[boundary..].into(),
        &[],
        0,
    );
    core.read_done(id, ReadEnd::Complete(MANIFEST), 0);
    let mut frames = Vec::new();
    let mut kinds = Vec::new();
    core.poll(0, 64, |outs| {
        outs.map(|out| {
            kinds.push(out.header.kind);
            if out.header.kind == Kind::Data {
                frames.push(Staged {
                    index: out.header.index,
                    offset: out.header.offset as usize,
                    len: out.header.datagram_len as usize,
                    bytes: [out.payload[0].bytes(), out.payload[1].bytes()].concat(),
                    pieces: out.payload.iter().filter(|piece| !piece.is_empty()).count(),
                    body_crc: out.body_crc,
                });
            }
        })
        .count()
    });
    drop(core);
    assert!(first && second, "premise: the core took both chunks");
    (frames, kinds)
}

/// The premises of one served object: START and three DATA frames, each carrying the object's bytes
/// at its offset, drawn from `pieces[index]` chunks.
fn check_premises(frames: &[Staged], kinds: &[Kind], pieces: [usize; 3]) {
    let data = object();
    assert_eq!(
        kinds,
        [Kind::Start, Kind::Data, Kind::Data, Kind::Data],
        "premise: one poll staged START and the three fragments"
    );
    for (at, frame) in frames.iter().enumerate() {
        assert_eq!(
            (frame.index as usize, frame.offset),
            (at, at * FRAGMENT),
            "premise: fragment {at} is staged at its own offset"
        );
        assert_eq!(
            frame.len,
            frame.bytes.len(),
            "premise: fragment {at} carries datagram_len payload bytes"
        );
        assert_eq!(
            frame.bytes,
            data[frame.offset..frame.offset + frame.len],
            "premise: fragment {at} carries the object's bytes at its offset"
        );
        assert_eq!(
            frame.pieces, pieces[at],
            "premise: the chunks fragment {at} draws from"
        );
    }
}

/// Every DATA frame's `body_crc` against the crc32c of the object's bytes `[offset, offset + len)`.
fn check_crcs(frames: &[Staged]) {
    let data = object();
    let crc = Crc32c::detect();
    let staged: Vec<(u32, u32)> = frames
        .iter()
        .map(|frame| (frame.index, frame.body_crc))
        .collect();
    let carried: Vec<(u32, u32)> = frames
        .iter()
        .map(|frame| {
            (
                frame.index,
                crc.checksum(&data[frame.offset..frame.offset + frame.len]),
            )
        })
        .collect();
    let mut distinct: Vec<u32> = carried.iter().map(|&(_, crc)| crc).collect();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(
        distinct.len(),
        carried.len(),
        "premise: the fragments' checksums differ pairwise, so a body crc taken from another \
         fragment's bytes fails: {carried:?}"
    );
    assert_eq!(
        staged, carried,
        "a DATA fragment's body crc is the crc32c of exactly the payload bytes it carries \
         (left: staged body_crc by fragment, right: crc32c of the carried bytes)"
    );
}

#[test]
fn a_fragment_spanning_two_chunks_carries_the_crc_of_its_bytes() {
    // Chunks of 12,000 and 8,000 bytes: fragment 1, bytes 8,192..16,384, spans both.
    let (frames, kinds) = staged(12_000);
    check_premises(&frames, &kinds, [1, 2, 1]);
    check_crcs(&frames);
}

#[test]
fn fragments_inside_one_chunk_carry_the_crc_of_their_bytes() {
    // The chunk boundary is the first fragment's end: every fragment lies inside one chunk.
    let (frames, kinds) = staged(FRAGMENT);
    check_premises(&frames, &kinds, [1, 1, 1]);
    check_crcs(&frames);
}
