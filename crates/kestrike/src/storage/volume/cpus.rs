//! Applying a [`CpuSet`] replaces a thread's affinity mask with the intersection of the set, available CPUs, and its cpuset's permitted CPUs. The kernel returns `EINVAL` if that intersection is empty and migrates the thread if its current CPU falls outside the resulting mask. A newly created thread inherits its creator's affinity mask.

use std::fmt;

pub const MAX_CPUS: usize = libc::CPU_SETSIZE as usize;

/// A requested CPU affinity mask with indices below `MAX_CPUS`; the kernel restricts the applied mask to available, cpuset-permitted CPUs.
#[derive(Clone, Copy)]
pub struct CpuSet(libc::cpu_set_t);

impl CpuSet {
    pub fn empty() -> Self {
        // SAFETY: All-zero bytes form a valid `cpu_set_t` representing an empty CPU set.
        Self(unsafe { std::mem::zeroed() })
    }

    pub fn from_cpus(cpus: &[usize]) -> Option<Self> {
        let mut set = Self::empty();
        for &cpu in cpus {
            if !set.insert(cpu) {
                return None;
            }
        }
        Some(set)
    }

    /// Returns the calling thread's affinity mask, including any affinity restrictions inherited from its creator.
    pub fn current() -> std::io::Result<Self> {
        let mut set = Self::empty();
        // SAFETY: `set.0` is a writable `cpu_set_t` of the size passed, and pid 0 names the calling thread.
        let rc = unsafe { libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &mut set.0) };
        if rc == 0 {
            Ok(set)
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    pub fn insert(&mut self, cpu: usize) -> bool {
        if cpu >= MAX_CPUS {
            return false;
        }
        // SAFETY: `cpu < CPU_SETSIZE`, so the bit lies inside the mask.
        unsafe { libc::CPU_SET(cpu, &mut self.0) };
        true
    }

    pub fn remove(&mut self, cpu: usize) {
        if cpu < MAX_CPUS {
            // SAFETY: `cpu < CPU_SETSIZE`, so the bit lies inside the mask.
            unsafe { libc::CPU_CLR(cpu, &mut self.0) };
        }
    }

    pub fn contains(&self, cpu: usize) -> bool {
        // SAFETY: the bound check runs first, so the bit read lies inside the mask.
        cpu < MAX_CPUS && unsafe { libc::CPU_ISSET(cpu, &self.0) }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        // SAFETY: `CPU_COUNT` reads only the mask's own words.
        unsafe { libc::CPU_COUNT(&self.0) as usize }
    }

    pub fn cpus(&self) -> impl Iterator<Item = usize> + '_ {
        (0..MAX_CPUS).filter(|&cpu| self.contains(cpu))
    }

    /// `apply_current` sets the calling thread's affinity mask to the intersection of this set, available CPUs, and
    /// CPUs permitted by the thread's cpuset.
    ///
    /// # Errors
    ///
    /// As [`apply`](Self::apply).
    pub fn apply_current(&self) -> std::io::Result<()> {
        // SAFETY: `pthread_self` names the calling thread, which stays live for the call.
        unsafe { self.apply(libc::pthread_self()) }
    }

    /// `apply` replaces `thread`'s affinity mask with the intersection of this set, available CPUs, and the thread's cpuset-permitted CPUs.
    ///
    /// # Errors
    ///
    /// The OS error code `pthread_setaffinity_np` returns, such as `EINVAL` when the set holds no CPU the thread's
    /// cpuset allows.
    ///
    /// # Safety
    ///
    /// `thread` names a thread that has not exited and stays running for the whole call: the caller's own thread, or one
    /// whose handle the caller holds unjoined and whose exit the caller rules out. An unjoined handle keeps only the
    /// descriptor valid; once its thread exited glibc applies the call to the calling thread, and a stale or invented
    /// identifier is undefined behavior.
    pub(super) unsafe fn apply(&self, thread: libc::pthread_t) -> std::io::Result<()> {
        // SAFETY: the caller guarantees `thread` stays live for the call, and `self.0` is a `cpu_set_t` of the size passed.
        let rc =
            unsafe { libc::pthread_setaffinity_np(thread, size_of::<libc::cpu_set_t>(), &self.0) };
        match rc {
            0 => Ok(()),
            code => Err(std::io::Error::from_raw_os_error(code)),
        }
    }

    /// # Safety
    ///
    /// `thread` names a thread that has not exited and stays running for the whole call, as [`apply`](Self::apply)
    /// requires.
    #[cfg(all(test, not(loom)))]
    pub(super) unsafe fn of(thread: libc::pthread_t) -> std::io::Result<Self> {
        let mut set = Self::empty();
        // SAFETY: the caller guarantees `thread` stays live for the call, and `set.0` is a writable `cpu_set_t` of the size passed.
        let rc = unsafe {
            libc::pthread_getaffinity_np(thread, size_of::<libc::cpu_set_t>(), &mut set.0)
        };
        match rc {
            0 => Ok(set),
            code => Err(std::io::Error::from_raw_os_error(code)),
        }
    }
}

impl PartialEq for CpuSet {
    fn eq(&self, other: &Self) -> bool {
        // SAFETY: `CPU_EQUAL` reads only the two masks' own words.
        unsafe { libc::CPU_EQUAL(&self.0, &other.0) }
    }
}

impl Eq for CpuSet {}

impl fmt::Debug for CpuSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.cpus()).finish()
    }
}
