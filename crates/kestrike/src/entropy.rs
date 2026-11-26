//! The operating system's entropy for 128-bit identifiers: each draw comes from `getrandom`, and `nonce_from` refuses an all-zero draw, because zero marks an absent identifier.

/// Why a 128-bit draw failed. `nonce_from(os_entropy)` returns only
/// `Unavailable` and `Zero`; a simulated entropy source returns `Refused`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyError {
    /// `getrandom` failed or filled fewer bytes than requested; `code` is
    /// the error number the call returned, or 0 for a short fill.
    Unavailable { code: i32 },
    /// The fill returned all zeros, which `nonce_from` refuses.
    Zero,
    /// A simulated entropy source refused the draw at `actor`'s entropy site
    /// `site` in `incarnation`.
    Refused {
        actor: u16,
        site: u16,
        incarnation: u32,
    },
}

/// Fills `bytes` from `getrandom`, retrying on `EINTR`; any other error is
/// `Unavailable` with its error number, and a short fill is `Unavailable`
/// with code 0.
pub(crate) fn os_entropy(bytes: &mut [u8; 16]) -> Result<(), EntropyError> {
    // From the urandom source, a request of at most 256 bytes blocks until the pool is initialized, then returns every byte; a signal during that wait fails the call with EINTR.
    loop {
        let got = getrandom(bytes);
        if got == bytes.len() as isize {
            return Ok(());
        }
        let code = if got < 0 { (-got) as i32 } else { 0 };
        if code == libc::EINTR {
            continue;
        }
        return Err(EntropyError::Unavailable { code });
    }
}

/// The aarch64 entropy path enters the Linux kernel directly through `svc`.
#[cfg(all(target_arch = "aarch64", not(miri)))]
fn getrandom(bytes: &mut [u8; 16]) -> isize {
    #[cfg(test)]
    crate::isa_witness::ran(crate::isa_witness::Kernel::EntropySvc);
    let ret: isize;
    // SAFETY: the Linux aarch64 system call ABI takes the number in x8 and the arguments in x0 to x2, and returns the result or a negated error number in x0. On return the kernel zeroes bits above 127 of z0-z31, all of p0-p15, and ffr; `clobber_abi("C")` marks v0-v31, p0-p15 and ffr clobbered, and each vN is the low 128 bits of zN, so the clobber of vN covers zN. The kernel writes at most `bytes.len()` bytes through the exclusive borrow.
    unsafe {
        core::arch::asm!(
            "svc #0",
            inlateout("x0") bytes.as_mut_ptr() as isize => ret,
            in("x1") bytes.len(),
            in("x2") 0usize,
            in("x8") libc::SYS_getrandom,
            clobber_abi("C"),
            options(nostack),
        );
    }
    ret
}

#[cfg(any(miri, not(target_arch = "aarch64")))]
fn getrandom(bytes: &mut [u8; 16]) -> isize {
    let got = libc_getrandom(bytes, 0);
    if got < 0 {
        -(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as isize)
    } else {
        got
    }
}

/// `libc::getrandom` over `bytes` with `flags`. Under test on Linux, an
/// installed script answers in the system call's place.
#[cfg(any(miri, not(target_arch = "aarch64")))]
#[inline(always)]
#[expect(
    clippy::disallowed_methods,
    reason = "mixed, cluster and recovery worlds supply the nonce fill; the long-run recorded upload draws host nonces, and whether its rows depend on them is unverified; syscall tests can script this libc draw"
)]
fn libc_getrandom(bytes: &mut [u8; 16], flags: u32) -> isize {
    #[cfg(all(test, target_os = "linux"))]
    if let Some(result) = syscall_tests::draw(bytes, flags) {
        return result;
    }
    // SAFETY: `bytes` is a valid writable buffer of `bytes.len()` bytes for the call's duration.
    unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), flags) }
}

#[cfg(all(test, target_os = "linux", any(miri, not(target_arch = "aarch64"))))]
mod syscall_tests;

/// A nonce filled by `fill`, refused when all zero.
pub(crate) fn nonce_from(
    fill: impl FnOnce(&mut [u8; 16]) -> Result<(), EntropyError>,
) -> Result<[u8; 16], EntropyError> {
    let mut nonce = [0; 16];
    fill(&mut nonce)?;
    if nonce == [0; 16] {
        return Err(EntropyError::Zero);
    }
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::os_entropy;
    use crate::isa_witness::{Detected, Kernel, runs, witness};

    /// The guards detect out-of-bounds writes that change either adjacent 16-byte
    /// region. A byte position the draw never writes stays zero in all eight
    /// draws; for a specified byte position the draw does write, eight independent
    /// uniform draws produce zero every time with probability 2^-64.
    #[test]
    fn an_entropy_draw_writes_exactly_its_sixteen_bytes() {
        const GUARD: u8 = 0xA5;
        let svc = cfg!(all(target_arch = "aarch64", not(miri)));
        let features = if cfg!(target_arch = "aarch64") {
            format!("aarch64 svc={svc}")
        } else {
            format!("host {} lacks aarch64", std::env::consts::ARCH)
        };
        let host = Detected {
            features,
            present: svc,
        };
        let mut seen = [0u8; 16];
        witness(
            "entropy-svc",
            host,
            || runs(Kernel::EntropySvc),
            || {
                for _ in 0..8 {
                    let mut wide = [GUARD; 48];
                    wide[16..32].fill(0);
                    let bytes: &mut [u8; 16] = (&mut wide[16..32]).try_into().unwrap();
                    os_entropy(bytes).unwrap();
                    for (seen, byte) in seen.iter_mut().zip(&wide[16..32]) {
                        *seen |= byte;
                    }
                    assert!(
                        wide[..16].iter().chain(&wide[32..]).all(|&b| b == GUARD),
                        "a draw wrote outside its buffer: {wide:?}"
                    );
                }
            },
        );
        assert!(
            seen.iter().all(|&b| b != 0),
            "a byte position stayed zero in every draw: {seen:?}"
        );
    }
}
