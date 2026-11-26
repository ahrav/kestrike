//! Facts about this host read from the kernel: online and usable CPUs,
//! memory, the wall clock, and the boot id with the `CLOCK_BOOTTIME`
//! milliseconds since that boot. A retry deadline pairs the two, because
//! the boot clock restarts at each boot.

use std::io;

pub fn online_cpus() -> u64 {
    // SAFETY: `sysconf` reads a system value and touches no memory of ours.
    let count = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    u64::try_from(count).unwrap_or(0)
}

pub fn usable_cpus() -> io::Result<u64> {
    let mut set = std::mem::MaybeUninit::<libc::cpu_set_t>::zeroed();
    // SAFETY: `set` is valid for writes of one `cpu_set_t`, whose size is
    // passed, and pid 0 names this thread.
    let read = unsafe {
        libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), set.as_mut_ptr())
    };
    if read != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the mask was zeroed and the call succeeded, so it is
    // initialized.
    let set = unsafe { set.assume_init() };
    // SAFETY: `CPU_COUNT` reads the initialized mask.
    Ok(u64::try_from(unsafe { libc::CPU_COUNT(&set) }).unwrap_or(0))
}

pub fn memory_bytes() -> io::Result<u64> {
    let text = std::fs::read_to_string("/proc/meminfo")?;
    text.lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))
        .and_then(|rest| rest.trim().strip_suffix("kB"))
        .and_then(|kib| kib.trim().parse::<u64>().ok())
        .map(|kib| kib.saturating_mul(1024))
        .ok_or_else(|| io::Error::other("/proc/meminfo holds no MemTotal line"))
}

pub fn now_s() -> u64 {
    now_ms() / 1000
}

/// The kernel's id of this boot, or an empty string when it cannot be
/// read.
pub fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|text| text.trim().to_owned())
        .unwrap_or_default()
}

/// Milliseconds of `CLOCK_BOOTTIME`, which counts from this boot and
/// includes suspended time; 0 when the clock cannot be read.
pub fn boot_ms() -> u64 {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `now` is a valid `timespec` for the call to fill.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut now) } != 0 {
        return 0;
    }
    u64::try_from(now.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1000)
        .saturating_add(u64::try_from(now.tv_nsec).unwrap_or(0) / 1_000_000)
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

pub fn random_hex(count: usize) -> io::Result<String> {
    let mut bytes = vec![0u8; count];
    let mut filled = 0;
    while filled < count {
        // SAFETY: the pointer and length name the unfilled tail of `bytes`.
        let read =
            unsafe { libc::getrandom(bytes[filled..].as_mut_ptr().cast(), count - filled, 0) };
        if read < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        filled += read.cast_unsigned();
    }
    Ok(crate::file::hex(&bytes))
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_host_reports_capacity_and_distinct_nonces() {
        assert!(super::online_cpus() >= 1);
        let usable = super::usable_cpus().expect("the affinity mask reads");
        assert!((1..=super::online_cpus()).contains(&usable));
        assert!(super::memory_bytes().expect("meminfo reads") > 0);
        let first = super::random_hex(16).expect("random bytes");
        assert_eq!(first.len(), 32);
        assert_ne!(first, super::random_hex(16).expect("random bytes"));
    }
}
