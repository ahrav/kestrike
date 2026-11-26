//! `parse` handles arbitrary bytes without panicking, reads only the supplied bytes, and refuses every input with the truncation flag set. For each accepted frame whose body crc holds, `encode` reproduces its header bytes.
//!
//! The target requires `judge`, which compares `parse` with the fixed-field reference decoder, to report agreement or `Unjudged` on each input with the truncation flag set and clear, and on a copy of each input of at least 192 bytes whose header crc the crate's checksum rewrites. The copy gives a mutated header a valid crc, so both decoders can accept it and `judge` compares their acceptance and decoded fields. An input the reference accepts carries the bitwise crc in that field, so the target requires the copy to keep the field, which holds while the crate's checksum computes crc32c. The round trip then runs on every copy both decoders accept, which includes every accepted input. libFuzzer saves the input the target received, and the target rebuilds the copy from it, so a failure on the copy replays from that file.
//!
//! Run from `crates/kestrike` with `cargo +nightly fuzz run frame -- -dict="$PWD/fuzz/frame.dict" -max_total_time=60`; `fuzz/frame.dict` holds the frame constants. On aarch64, cargo-fuzz sets `RUSTFLAGS` for its build in place of the flags of `.cargo/config.toml` and appends the caller's value, so the command runs as `env -u CARGO_ENCODED_RUSTFLAGS RUSTFLAGS="-C target-feature=+lse" cargo +nightly fuzz run frame ...`, since a set `CARGO_ENCODED_RUSTFLAGS` would replace both. `corpus/frame` seeds at least one canonical frame of every kind in its `v3-` files and, in its `reject-` files, which the frame seed tests write and check, one frame per refusal reason of the decoder, with the truncation reason reached by the truncated parse of every input. Its unprefixed tracked files are version 2 frames, which the decoder refuses as an unknown version. The fuzz package's `.gitignore` keeps the inputs a run adds there out of the repository.

#![no_main]

use kestrike::net::{Frame, HEADER_LEN, Verdict, encode, judge, parse};
use kestrike::storage::Crc32c;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let crc = Crc32c::detect();
    assert!(
        parse(crc, data, true).is_err(),
        "a truncated datagram never parses"
    );
    assert_eq!(
        agrees(crc, data, true, "raw"),
        Verdict::Agree { accepted: false },
        "both decoders refuse a truncated datagram"
    );
    let raw = agrees(crc, data, false, "raw");
    if data.len() >= HEADER_LEN {
        let mut resealed = data.to_vec();
        resealed[160..164].fill(0);
        let crc_value = crc.checksum(&resealed[..176]);
        resealed[160..164].copy_from_slice(&crc_value.to_be_bytes());
        if matches!(raw, Verdict::Agree { accepted: true } | Verdict::Unjudged) {
            assert_eq!(
                resealed[160..164],
                data[160..164],
                "resealing a header the reference accepts keeps its crc"
            );
        }
        if agrees(crc, &resealed, false, "resealed") == (Verdict::Agree { accepted: true }) {
            let frame = parse(crc, &resealed, false).expect("an agreed acceptance parses");
            round_trip(crc, &frame, &resealed);
        }
    }
});

fn agrees(crc: Crc32c, bytes: &[u8], truncated: bool, input: &str) -> Verdict {
    let verdict = judge(crc, bytes, truncated);
    assert!(
        matches!(verdict, Verdict::Agree { .. } | Verdict::Unjudged),
        "parse and the reference decoder disagree: {verdict:?} on the {input} input, truncated {truncated}"
    );
    verdict
}

/// A parsed header encodes again, and a frame whose body crc holds encodes to its own header bytes.
fn round_trip(crc: Crc32c, frame: &Frame<'_>, data: &[u8]) {
    let body = frame.raw_body();
    assert_eq!(body.len(), data.len() - HEADER_LEN);
    let mut out = [0u8; HEADER_LEN];
    encode(crc, &frame.header(), [body, &[]], &mut out).expect("a parsed header is canonical");
    if frame.check_body(crc).is_ok() {
        assert_eq!(&out[..], &data[..HEADER_LEN], "canonical bytes round-trip");
    }
}
