//! The IPv4 checksum shim under both native configurations: the ordinary
//! install and the address-sanitized one, whose instrumentation reaches the
//! shim's own reads.

use crate::{rte_ipv4_hdr, spdk_sys_rte_ipv4_cksum};

/// The bytes of an IPv4 header, at the two-byte alignment `rte_ipv4_hdr`
/// declares.
#[repr(C, align(2))]
struct Header([u8; 20]);

/// A header whose checksum field is clear: version 4, IHL 5, total length
/// 115, identification 0, flags and fragment offset 0x4000, TTL 64, UDP,
/// source 192.168.0.1, destination 192.168.0.199. Its checksum is 0xb861
/// in network order.
const GOLDEN: Header = Header([
    0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01,
    0xc0, 0xa8, 0x00, 0xc7,
]);

fn checksum(header: &Header) -> [u8; 2] {
    // SAFETY: `header` is 20 initialized bytes at the size and alignment of
    // `rte_ipv4_hdr`, and the shim reads the header through a pointer to
    // them.
    let sum = unsafe { spdk_sys_rte_ipv4_cksum(header.0.as_ptr().cast::<rte_ipv4_hdr>()) };
    sum.to_ne_bytes()
}

#[test]
fn the_golden_header_checksums_to_its_published_value() {
    assert_eq!(checksum(&GOLDEN), [0xb8, 0x61]);
    let mut complete = GOLDEN;
    complete.0[10..12].copy_from_slice(&[0xb8, 0x61]);
    assert_eq!(
        checksum(&complete),
        [0, 0],
        "a header carrying its checksum sums to zero"
    );
    let mut altered = GOLDEN;
    altered.0[8] = 63;
    assert_ne!(checksum(&altered), [0xb8, 0x61]);
}

#[cfg(spdk_sys_asan)]
const OVERFLOW_CHILD: &str =
    "shim_tests::an_overflow_child_reads_a_header_from_a_one_byte_allocation";
#[cfg(spdk_sys_asan)]
const OVERFLOW_MARKER: &str = "SPDK_SYS_OVERFLOW_CHILD";

#[cfg(spdk_sys_asan)]
#[test]
fn an_overflow_child_reads_a_header_from_a_one_byte_allocation() {
    if std::env::var_os(OVERFLOW_MARKER).is_none() {
        return;
    }
    let layout = std::alloc::Layout::from_size_align(1, 2).unwrap();
    // SAFETY: a one-byte layout has a nonzero size; its alignment is the
    // header's, so the size is the one contract the read below violates.
    let byte = unsafe { std::alloc::alloc(layout) };
    assert!(!byte.is_null());
    // SAFETY: the one allocated byte is written, so the IHL the shim reads
    // first is initialized and names a 20-byte header.
    unsafe { byte.write(0x45) };
    // SAFETY: deliberately violated: the shim reads 20 bytes of a one-byte
    // allocation, which address sanitizer reports and aborts on before the
    // read's result is used.
    let sum = unsafe { spdk_sys_rte_ipv4_cksum(byte.cast::<rte_ipv4_hdr>()) };
    std::println!("checksum {sum:#06x} escaped the sanitizer");
    // SAFETY: `byte` came from `alloc` with `layout`.
    unsafe { std::alloc::dealloc(byte, layout) };
}

#[cfg(spdk_sys_asan)]
#[test]
fn a_one_byte_header_read_is_reported_at_the_shim_frame() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", OVERFLOW_CHILD, "--test-threads=1", "--nocapture"])
        .env(OVERFLOW_MARKER, "1")
        .output()
        .unwrap();
    let stderr = std::string::String::from_utf8_lossy(&output.stderr);
    let stdout = std::string::String::from_utf8_lossy(&output.stdout);
    let lines: std::vec::Vec<&str> = stderr.lines().collect();
    assert!(
        !output.status.success(),
        "the child exited {:?}:\n{stdout}\n{stderr}",
        output.status
    );
    for needle in [
        "AddressSanitizer",
        "heap-buffer-overflow",
        "spdk_sys_rte_ipv4_cksum",
    ] {
        assert!(
            lines.iter().any(|line| line.contains(needle)),
            "the report names {needle}:\n{stderr}"
        );
    }
    assert!(
        !stdout.contains("escaped the sanitizer"),
        "the read was reported before its result was used:\n{stdout}"
    );
}
