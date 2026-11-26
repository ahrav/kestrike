//! Records as they lie on the device, and the checks a reader applies before trusting any byte of one.
//!
//! Invariants owned by this module:
//!
//! - A record contains a header, then metadata and body, followed by padding to the unit. The payload immediately follows the header, which occupies `header_bytes(payload_len, chunk_len)` bytes. Each chunk fits within one record-aligned `chunk_len`-byte window; chunk boundaries after the first occur at multiples of `chunk_len` from the record start.
//! - One mechanism computes every checksum, chosen by [`Crc32c::detect`], which returns the same mechanism on every call in a process; every mechanism computes the same function, and incremental updates finish to the one-shot value.
//! - An encoded header carries magic, version, key, allocation (slot index and incarnation), session, cache version, both lengths, the chunk parameters, the extent index, verified length and absolute offset, a context crc32c, and one crc32c per chunk, zeros past the chunk count, protected by its own crc32c.
//! - Verification derives the layout from the header's own lengths and checks, in order: magic, version, the lengths against the extent's units, the verified length, the chunk parameters, the header crc over the derived span, then the identity through the read predicate, extent index, offset and context crc, returning the first failure as its own [`HeaderMismatch`] variant.
//!   On a volume read, verification establishes identity and position before payload checks or exposure; chunk checks require the returned `VerifiedHeader`.
//! - Encoding, checksums and verification are pure functions over caller buffers and allocate nothing.
//! - [`inspect()`] scans a bounded window of an image read-only and reports what each candidate record's bytes claim and the first check they fail; its findings are observations that carry no live or recovery authority.

mod arithmetic;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod claim_fuzz_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod claim_session_tests;
#[cfg(test)]
mod context_crc_cover_tests;
mod crc32c;
#[cfg(test)]
mod crc32c_arms_tests;
#[cfg(test)]
mod crc32c_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod crc_reference_tests;
#[cfg(test)]
mod division_rule_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) mod fuzz_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod geometry_fuzz_tests;
mod header;
#[cfg(test)]
mod header_check_order_tests;
#[cfg(test)]
mod header_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod inspect;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod inspect_replaced_record_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod inspect_tests;
#[cfg(test)]
mod key_bits_tests;
mod layout;
#[cfg(test)]
mod layout_tests;
mod predicate;
#[cfg(test)]
mod predicate_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod scan_fuzz_tests;
#[cfg(test)]
mod sealed_header_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod vector_tests;
mod window;
#[cfg(test)]
mod window_tests;

#[cfg(test)]
pub(crate) use crc32c::take_zero_run_builds;
pub use crc32c::{Crc32c, RunningCrc, ZeroRun, ZeroRuns};
#[cfg(test)]
pub(crate) use header::{ChunkMismatch, EncodeError, claim_header, framing};
pub(crate) use header::{
    ExpectedHeader, ExtentPosition, admits, check_header, encode_header, feed_header,
    put_chunk_crc, seal_header, verify_header,
};
pub use header::{HeaderMismatch, RecordIdentity};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use inspect::{Finding, Image, Report, Verdict, Window, WindowError, inspect};
pub(crate) use layout::RecordPricer;
pub use layout::{RecordConfig, RecordConfigError, RecordLayout, ValidRecordConfig};
pub(crate) use layout::{first_window_end, header_bytes};
pub(crate) use window::window_crc;
