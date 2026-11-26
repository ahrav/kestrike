//! The tests cover ACK receipt masks at distances `d = bound - base` in
//! `0..=66`, for GET's ACK, whose bound is the count, and PUT ACK, whose
//! bound is the grant. The masks are zero, each bit `i` in `0..64` alone,
//! each run of low bits, and scattered bits. The tests compute the
//! expectation `i + 1 < d` for every set bit in `i128` from the frame's own
//! fields and check every case with both the parser and the encoder.

use super::datagram::HEADER_LEN;
use super::frame::{Field, FrameError, Kind, encode, parse};
use super::frame_tests::{Raw, crc, header_of};

/// Whether bit `bit` of a receipt mask may be set over `base` and `bound`:
/// it names fragment `base + 1 + bit`, which must lie below `bound`.
fn allowed(bit: u32, base: u32, bound: u32) -> bool {
    i128::from(base) + 1 + i128::from(bit) < i128::from(bound)
}

/// Whether every set bit of `mask` is [`allowed`] over `base` and `bound`.
fn within(mask: u64, base: u32, bound: u32) -> bool {
    (0..u64::BITS)
        .filter(|bit| mask >> bit & 1 == 1)
        .all(|bit| allowed(bit, base, bound))
}

/// Zero, every one-bit mask, the lowest `n` bits for every `n`, and
/// scattered bits.
fn masks() -> Vec<u64> {
    let mut masks = vec![0];
    masks.extend((0..u64::BITS).map(|bit| 1u64 << bit));
    masks.extend((2..u64::BITS).map(|bits| (1u64 << bits) - 1));
    masks.extend([
        u64::MAX,
        0xaaaa_aaaa_aaaa_aaaa,
        0x5555_5555_5555_5555,
        0x8000_0000_0000_0001,
        0xffff_ffff_0000_0000,
        0x0000_0000_0001_0100,
    ]);
    masks
}

/// A GET ACK of a `count`-fragment object at receipt `base` carrying `mask`.
fn get_ack_of(count: u32, base: u32, mask: u64) -> Raw {
    let mut ack = Raw::manifest(8, 0, count * 8192);
    assert_eq!(ack.count, count);
    ack.index = base;
    ack.offset = mask;
    ack
}

/// A GET ACK of a 100-fragment object at receipt `base` carrying `mask`.
fn get_ack(base: u32, mask: u64) -> Raw {
    get_ack_of(100, base, mask)
}

/// A PUT ACK of a 5000-fragment object at receipt `base` and `grant`
/// carrying `mask`.
fn put_ack(base: u32, grant: u32, mask: u64) -> Raw {
    let mut ack = Raw::put(17, 0, 5000 * 8192);
    ack.index = base;
    ack.grant = grant;
    ack.offset = mask;
    ack
}

/// The parser's verdict on `raw`'s bytes, after checking that the encoder
/// reaches the same verdict on its header and, on success, writes those
/// bytes.
fn verdict(raw: &Raw) -> Result<(), FrameError> {
    let bytes = raw.bytes();
    let parsed = parse(crc(), &bytes, false).map(|_| ());
    let mut out = [0; HEADER_LEN];
    let encoded = encode(crc(), &header_of(raw), [&[], &[]], &mut out);
    assert_eq!(encoded, parsed, "the encoder and the parser disagree");
    if encoded.is_ok() {
        assert_eq!(out[..], bytes[..HEADER_LEN]);
    }
    parsed
}

fn refused(kind: Kind, field: Field) -> Result<(), FrameError> {
    Err(FrameError::Field { kind, field })
}

/// For `count - base` in `0..=66`, a GET ACK carrying a mask from `masks()`
/// parses exactly when every set bit identifies a fragment below `count`.
/// Otherwise, the parser reports an error at the mask field. At distances 0
/// and 1, only the zero mask parses.
#[test]
fn ib_receipt_mask_bounds_get_ack_matrix() {
    let masks = masks();
    let (mut accepted, mut refusals) = (0, 0);
    for count in [1, 2, 3, 64, 65, 100, 200] {
        for distance in 0..=66.min(count) {
            let base = count - distance;
            for &mask in &masks {
                let fits = within(mask, base, count);
                assert!(distance > 1 || fits == (mask == 0));
                let expected = match fits {
                    true => Ok(()),
                    false => refused(Kind::Ack, Field::Offset),
                };
                assert_eq!(
                    verdict(&get_ack_of(count, base, mask)),
                    expected,
                    "count {count} d {distance} mask {mask:#018x}"
                );
                accepted += usize::from(fits);
                refusals += usize::from(!fits);
            }
        }
    }
    assert!(accepted > 0 && refusals > 0);
}

/// For `grant - base` in `0..=66`, a PUT ACK carrying a mask from `masks()`
/// parses exactly when every set bit identifies a fragment below `grant`.
/// Otherwise, the parser reports an error at the mask field. Each grant is
/// either below `count` or at `count`.
#[test]
fn ib_receipt_mask_bounds_put_ack_matrix() {
    let masks = masks();
    let (mut accepted, mut refusals) = (0, 0);
    for grant in [1, 2, 3, 64, 65, 100, 200, 4999, 5000] {
        for distance in 0..=66.min(grant) {
            let base = grant - distance;
            for &mask in &masks {
                let fits = within(mask, base, grant);
                assert!(distance > 1 || fits == (mask == 0));
                let expected = match fits {
                    true => Ok(()),
                    false => refused(Kind::PutAck, Field::Offset),
                };
                assert_eq!(
                    verdict(&put_ack(base, grant, mask)),
                    expected,
                    "grant {grant} d {distance} mask {mask:#018x}"
                );
                accepted += usize::from(fits);
                refusals += usize::from(!fits);
            }
        }
    }
    assert!(accepted > 0 && refusals > 0);
}

/// Zero and full masks, equal bounds, a base beyond its bound and `u32`
/// edges, each parsing or refusing at the first field that fails in its
/// kind's check order.
#[test]
fn ib_receipt_mask_bounds_edges() {
    let full = |distance: u32| match distance {
        0 | 1 => 0,
        d if d >= 65 => u64::MAX,
        d => (1u64 << (d - 1)) - 1,
    };
    for distance in 0..=65u32 {
        // Every allowed bit at once parses; one more bit refuses.
        assert_eq!(verdict(&get_ack(100 - distance, full(distance))), Ok(()));
        assert_eq!(
            verdict(&put_ack(200 - distance, 200, full(distance))),
            Ok(())
        );
        if distance < 65 {
            let over = full(distance) | 1 << distance.saturating_sub(1);
            assert_eq!(
                verdict(&get_ack(100 - distance, over)),
                refused(Kind::Ack, Field::Offset)
            );
            assert_eq!(
                verdict(&put_ack(200 - distance, 200, over)),
                refused(Kind::PutAck, Field::Offset)
            );
        }
    }
    // A zero mask parses at equal bounds; any bit there refuses.
    assert_eq!(verdict(&get_ack(100, 0)), Ok(()));
    assert_eq!(verdict(&put_ack(200, 200, 0)), Ok(()));
    assert_eq!(
        verdict(&get_ack(100, 1 << 63)),
        refused(Kind::Ack, Field::Offset)
    );
    // A base beyond the count refuses at the base with a zero mask and at
    // the mask with any bit, since the mask is checked first on GET.
    assert_eq!(verdict(&get_ack(101, 0)), refused(Kind::Ack, Field::Index));
    assert_eq!(verdict(&get_ack(101, 1)), refused(Kind::Ack, Field::Offset));
    // PUT checks the base against the count, then the grant, then the mask.
    assert_eq!(
        verdict(&put_ack(201, 200, 0)),
        refused(Kind::PutAck, Field::Grant)
    );
    assert_eq!(
        verdict(&put_ack(5001, 5001, 0)),
        refused(Kind::PutAck, Field::Index)
    );
    // `u32` edges. GET checks the mask first, so a base of `u32::MAX`
    // refuses at the mask, since the codec forms `base + 1` in `u64`, or at
    // the base with a zero mask. PUT checks the base and the grant against the
    // count of 5000 first, so it refuses such a base at the index and such
    // a grant at the grant.
    for mask in [0, 1, u64::MAX] {
        let field = if mask == 0 {
            Field::Index
        } else {
            Field::Offset
        };
        assert_eq!(verdict(&get_ack(u32::MAX, mask)), refused(Kind::Ack, field));
        assert_eq!(
            verdict(&put_ack(u32::MAX, u32::MAX, mask)),
            refused(Kind::PutAck, Field::Index)
        );
        assert_eq!(
            verdict(&put_ack(4999, u32::MAX, mask)),
            refused(Kind::PutAck, Field::Grant)
        );
    }
}
