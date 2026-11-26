//! [`accepts`] decides whether a verified header's identity is the record an index entry names, readable by a
//! reader of session `g·2^32 + a`.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

/// Whether a record whose header names `found` (allocation word, session, cache version) is accepted by a reader of
/// session `reader` for the index entry naming `named`.
#[cfg_attr(verus_keep_ghost, verus_spec(accepted =>
    ensures
        accepted <==> found.0 == named.0
            && found.1 == named.1
            && found.2 == named.2
            && found.1 / 0x1_0000_0000 == reader / 0x1_0000_0000
            && (found.1 % 0x1_0000_0000) % 2 == 0
            && found.1 % 0x1_0000_0000 != 0
            && found.1 % 0x1_0000_0000 <= reader % 0x1_0000_0000,
))]
pub(crate) fn accepts(found: (u64, u64, u64), named: (u64, u64, u64), reader: u64) -> bool {
    let session = found.1;
    #[cfg(verus_keep_ghost)]
    proof! {
        assert(session >> 32u64 == session / 0x1_0000_0000u64) by (bit_vector);
        assert(reader >> 32u64 == reader / 0x1_0000_0000u64) by (bit_vector);
        assert(session & 0xFFFF_FFFFu64 == session % 0x1_0000_0000u64) by (bit_vector);
        assert(reader & 0xFFFF_FFFFu64 == reader % 0x1_0000_0000u64) by (bit_vector);
        assert((session & 1u64 == 0u64) == ((session % 0x1_0000_0000u64) % 2u64 == 0u64)) by (bit_vector);
    }
    let epoch = session & 0xFFFF_FFFF;
    found.0 == named.0
        && session == named.1
        && found.2 == named.2
        && session >> 32 == reader >> 32
        && session & 1 == 0
        && epoch != 0
        && epoch <= reader & 0xFFFF_FFFF
}
