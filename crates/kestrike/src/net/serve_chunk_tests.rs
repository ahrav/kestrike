//! A chunk's verified window checksums are at most the core's `windows`, which `ServeCore::chunk_with_digests` asserts in a debug build before it copies a checksum row.

use std::ops::Range;
use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::net::requests::{RequestId, RequestTable};
use crate::net::serve_tests::{CONFIG, Core, get, payload, session};
use crate::net::served::Request;
use crate::storage::EngineBudget;

use super::{GetOutcome, HELD_CHUNKS, Manifest};

type Chunk = Box<[u8]>;

const MANIFEST: Manifest = Manifest {
    allocation: 7,
    metadata_len: 0,
    body_len: 4096,
};

/// A core whose `windows` is 1, with a live GET whose read started and that holds no chunk, so its first checksum row is free.
fn live() -> (Core<Chunk>, RequestId) {
    let table = RequestTable::<Request<Chunk>>::new(4, 2, 2);
    let mut budget = EngineBudget::new(1 << 20);
    let mut core = Core::new(CONFIG, table, 2, 128, 0, 1, &mut budget).unwrap();
    let GetOutcome::Read { id, .. } = core.get(session(1), &get(0, 1, 1), 0) else {
        panic!("a new request");
    };
    core.read_started(id);
    assert_eq!(core.serve.windows, 1);
    const { assert!(HELD_CHUNKS >= 2, "two checksum rows per request") };
    assert!(rows(&core, id).len() >= 2);
    assert_eq!(core.retained(id), 0, "the first row is free");
    assert!(
        !core.serve.window_crcs.contains(&0xA5A5_0001)
            && !core.serve.window_crcs.contains(&0xA5A5_0002),
        "the table holds neither checksum before the chunk"
    );
    (core, id)
}

/// The indexes of the checksum table that hold the rows of request `id`.
fn rows(core: &Core<Chunk>, id: RequestId) -> Range<usize> {
    let block = HELD_CHUNKS * core.serve.windows;
    let first = usize::from(id.slot()) * block;
    first..first + block
}

/// The control: a chunk with one checksum, the core's `windows`, is taken, and exactly one entry of the whole checksum table changes, inside the request's rows, to that checksum.
#[test]
fn a_chunk_with_as_many_checksums_as_the_cores_windows_is_taken() {
    let (mut core, id) = live();
    let before = core.serve.window_crcs.to_vec();
    let bytes: Chunk = payload(1024).into();
    assert!(core.chunk(id, MANIFEST, 0..1024, bytes, &[0xA5A5_0001], 1));
    assert_eq!(core.retained(id), 1);
    let after = &core.serve.window_crcs;
    assert_eq!(after.len(), before.len());
    let written: Vec<(usize, u32)> = (after.iter().zip(&before).enumerate())
        .filter(|(_, (now, was))| now != was)
        .map(|(index, (now, _))| (index, *now))
        .collect();
    let [(index, value)] = written[..] else {
        panic!("one entry of the table is written: {written:?}");
    };
    assert!(
        rows(&core, id).contains(&index),
        "the entry lies in the request's rows"
    );
    assert_eq!(value, 0xA5A5_0001);
}

/// A chunk with two checksums on a core whose `windows` is 1 stops at the assertion in a debug build, before any checksum row is written, though the two entries would fit the request's allocated rows.
#[test]
#[cfg(debug_assertions)]
fn a_chunk_with_more_checksums_than_the_cores_windows_stops_before_the_copy() {
    let (mut core, id) = live();
    let before = core.serve.window_crcs.to_vec();
    let bytes: Chunk = payload(1024).into();
    let stopped = catch_unwind(AssertUnwindSafe(|| {
        core.chunk(id, MANIFEST, 0..1024, bytes, &[0xA5A5_0001, 0xA5A5_0002], 1)
    }));
    let message = match stopped {
        Ok(more) => panic!(
            "the chunk was taken (read continues: {more}); rows {:?}",
            &core.serve.window_crcs[rows(&core, id)]
        ),
        Err(panic) => panic
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_owned()))
            .expect("a panic message"),
    };
    assert!(
        message.contains("a chunk spans at most the core's windows"),
        "{message}"
    );
    assert_eq!(
        core.serve.window_crcs[..],
        before[..],
        "no row of any request is written"
    );
    assert_eq!(core.retained(id), 0, "no chunk is held");
}
