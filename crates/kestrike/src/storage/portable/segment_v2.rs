//! The production physical-clock provider: a reader of the bounded-clock daemon's protocol v2 segment, a file of 80 bytes the daemon rewrites in place.
//!
//! The segment: a 16-byte header of magic (8 bytes), segment size (`u32`), layout version (`u16`) and a 16-bit generation, then a 64-byte body of the `as_of` and `void_after` instants on `CLOCK_MONOTONIC_COARSE` (each `i64` seconds and `i64` nanoseconds), the bound on `CLOCK_REALTIME`'s error at `as_of` (`i64` nanoseconds), the hypervisor's disruption marker (`u64`), the drift rate in parts per billion (`u32`), the clock status (`i32`), the disruption-support flag (`u8`) and seven bytes of padding. The reader decodes it as little-endian, as the daemon writes it on x86-64 and little-endian AArch64 hosts; on a big-endian AArch64 host the magic never matches, so every header reads as rewriting and no reading is trusted.
//! The daemon writes the body between two generation stores, odd before and even after, skips zero on rollover, writes zero when it wipes the file, and rewrites the same path in place on restart, so a descriptor opened once stays valid.
//!
//! Each attempt reads the header, the body and the header again, three `pread` calls into stack buffers, and accepts the body only when both generations are equal, even and nonzero; it then reads `CLOCK_REALTIME` and the suspend bracket `CLOCK_MONOTONIC` (m1), `CLOCK_BOOTTIME` (b), `CLOCK_MONOTONIC` (m2), which places the boot offset in `[b - m2, b - m1]`, with the lower bound raised to zero because boot time never runs behind monotonic time; a short read, a torn or rewritten body or a bracket wider than the validated limit fails the attempt. After at most `read_attempts` failed attempts the reader re-evaluates its cached snapshot with one more clock read. The snapshot is the last consistent header and body any attempt read, so a restarted daemon's sequence that returns to a cached generation still replaces the body.
//! Every bracket since construction, the one construction takes included, is compared with the one before it: a lower bound above the previous upper bound shows a suspend between them, and from then on only a snapshot whose `as_of` lies at or after that bracket's m2 is trusted; before any suspend shows, only a snapshot whose `as_of` lies at or after the first bracket's m2, one the daemon wrote after the reader was constructed. Jitter between the three clock reads only widens a bracket and never marks a reading untrusted.
//! A reading is trusted only when the snapshot's status is synchronized or free-running, its `as_of` lies at or before m1 and its void-after instant at or after it, disruption support is on, the hypervisor's marker equals the snapshot's, neither construction nor a detected suspend separates `as_of` from now, and `Host::writer_stores_ordered` returns `true`; the bound then grows from `as_of` to m1 by the drift rate with integer ceiling arithmetic in `u128`. The fine m1, read after the realtime sample, lies at or after the coarse clock the daemon's instants use, so the growth covers the realtime sample.
//!
//! On 64-bit Linux, x86-64 and AArch64 construct a reader, and every other architecture refuses. The consistency check rests on one fact per target: the executing CPU observes the kernel's loads inside the three `pread` calls in system-call order. x86-64 orders loads with loads. On AArch64 `Reader::attempt` calls `order_loads`, a `dmb ishld`, after the first header read and after the body read, and `dmb ishld` orders the executing CPU's loads inside one `pread` before its loads inside the next. The system-call entry and the exception return are context-synchronization events; the barrier alone supplies the memory order between the calls.
//!
//! On x86-64 the reader assumes every CPU observes the daemon's stores in order: odd generation, body, even generation. A violation can let an attempt accept parts of two updates between equal even generations. `LinuxHost::writer_stores_ordered` returns `true` only on x86-64, so on AArch64 the reader marks every reading that passes the other checks untrusted as `UnorderedWriter`. On both targets the reader assumes, as the Linux scheduler's program-order notes state, that a task's release and acquire chain across a CPU migration, through the runqueue locks for a runnable task and through the `on_cpu` store and load for a woken one, keeps the program order of two reads the migration separates, since each attempt runs on one OS thread. It assumes the counter read behind `clock_gettime` is ordered with the reader's loads: on AArch64, after earlier loads by the read barrier that opens the vDSO's seqcount read and the control dependency from the vDSO's later clock-mode load into the instruction barrier before the counter read, or into the counter read itself on hardware whose counter read is self-synchronizing, and before later loads by the address dependency after it together with the read barrier of the seqcount retry; on x86-64, by the vDSO's ordered `rdtsc` read; and on either target by the kernel's own counter read when `clock_gettime` falls back to the system call. It assumes `pread` on the segment's tmpfs file copies with explicit loads from the shared page on the executing CPU, and that each header read takes the 16-bit generation from one daemon store. It assumes the daemon's update rate times the longest stall between one attempt's two header reads stays below 32,767 updates, the number of nonzero even generations, so a 16-bit generation cannot return to its first value inside one attempt, and that every suspend lasts longer than twice the bracket limit, the shortest a bracket pair detects. The segment names no time scale, so the caller names the scale the host's realtime clock follows, which the host's time source fixes.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use super::super::os::order_loads;
use super::clock::{ClockScale, PhysicalClock, Reading, Trust, Untrusted};
use super::expiry::NANOS_PER_SECOND;

/// The segment's default path.
pub const DEFAULT_SEGMENT: &str = "/var/run/clockbound/shm0";
/// The hypervisor clock device's default path, whose disruption marker the reader compares with the segment's.
pub const DEFAULT_MARKER: &str = "/dev/vmclock0";

/// The magic number as the daemon writes it: two native-endian `u32` values, `0x414D_5A4E` and `0x4342_0200`, laid out little-endian on x86-64 and little-endian AArch64 hosts.
const MAGIC: [u8; 8] = [0x4E, 0x5A, 0x4D, 0x41, 0x00, 0x02, 0x42, 0x43];
pub(crate) const HEADER_LEN: usize = 16;
pub(crate) const BODY_LEN: usize = 64;
const SEGMENT_LEN: u32 = 80;
const VERSION: u16 = 2;
const MARKER_MAGIC: u32 = 0x4B4C_4356;
pub(crate) const MARKER_LEN: usize = 24;

const SYNCHRONIZED: i32 = 1;
const FREE_RUNNING: i32 = 2;
const DISRUPTED: i32 = 3;

/// A clock the reader samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClockId {
    Realtime,
    Monotonic,
    Boottime,
}

/// What a reader reads from its host: positioned reads of the segment and the marker device, and clock samples in nanoseconds.
pub(crate) trait Host {
    /// Reads into `bytes` from offset `at` of the segment; the byte count, or `None` when the segment is absent or the read fails.
    fn segment(&mut self, at: u64, bytes: &mut [u8]) -> Option<usize>;
    /// Reads the marker device's first bytes into `bytes`; the byte count, or `None` when the device is absent or the read fails.
    fn marker(&mut self, bytes: &mut [u8]) -> Option<usize>;
    fn clock(&mut self, clock: ClockId) -> Option<u64>;
    /// Reports whether every CPU observes the segment writer's odd generation store before every body store and every body store before its even generation store.
    fn writer_stores_ordered(&self) -> bool;
}

/// The segment's body fields, times in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Body {
    pub(crate) as_of: u64,
    pub(crate) void_after: u64,
    pub(crate) bound: u64,
    pub(crate) marker: u64,
    pub(crate) drift_ppb: u32,
    pub(crate) status: i32,
    pub(crate) disruption_support: bool,
}

/// What one segment header shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Header {
    Generation(u16),
    /// Another magic number or generation zero, as a wiped or rewritten file shows while the daemon restarts; the attempt fails.
    Rewriting,
    /// A cause the reading reports at once.
    Refused(Untrusted),
}

pub(crate) fn header(bytes: &[u8; HEADER_LEN]) -> Header {
    let generation = u16::from_le_bytes(field(bytes, 14));
    if bytes[..8] != MAGIC || generation == 0 {
        return Header::Rewriting;
    }
    if u16::from_le_bytes(field(bytes, 12)) != VERSION {
        return Header::Refused(Untrusted::Unsupported);
    }
    if u32::from_le_bytes(field(bytes, 8)) < SEGMENT_LEN {
        return Header::Refused(Untrusted::Missing);
    }
    Header::Generation(generation)
}

/// The `N` bytes of `bytes` from offset `at`.
fn field<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    let mut field = [0; N];
    field.copy_from_slice(&bytes[at..at + N]);
    field
}

/// The body's fields; `Malformed` for a negative or invalid time, a negative bound, a drift rate of `1e9` parts per billion or more, or a support flag other than 0 or 1.
pub(crate) fn body(bytes: &[u8; BODY_LEN]) -> Result<Body, Untrusted> {
    let word = |at: usize| i64::from_le_bytes(field(bytes, at));
    let instant = |at: usize| {
        let (seconds, nanos) = (word(at), word(at + 8));
        let seconds = u64::try_from(seconds).ok()?;
        let nanos = u64::try_from(nanos)
            .ok()
            .filter(|n| *n < NANOS_PER_SECOND)?;
        seconds.checked_mul(NANOS_PER_SECOND)?.checked_add(nanos)
    };
    let drift_ppb = u32::from_le_bytes(field(bytes, 48));
    let (Some(as_of), Some(void_after), Ok(bound)) =
        (instant(0), instant(16), u64::try_from(word(32)))
    else {
        return Err(Untrusted::Malformed);
    };
    if u64::from(drift_ppb) >= NANOS_PER_SECOND {
        return Err(Untrusted::Malformed);
    }
    let disruption_support = match bytes[56] {
        0 => false,
        1 => true,
        _ => return Err(Untrusted::Malformed),
    };
    Ok(Body {
        as_of,
        void_after,
        bound,
        marker: word(40) as u64,
        drift_ppb,
        status: i32::from_le_bytes(field(bytes, 52)),
        disruption_support,
    })
}

/// One attempt's segment read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Attempt {
    Fresh(u16, Body),
    /// A short read, another magic number, or generations unequal, odd or zero; `short` for a short or failed read.
    Retry {
        short: bool,
    },
    Refused(Untrusted),
}

/// The clock samples of one attempt: realtime, then the suspend bracket's two monotonic samples around the boot-time sample, which place the boot offset in `[offset_low, offset_high]`.
#[derive(Debug, Clone, Copy)]
struct Clocks {
    real: u64,
    /// The first monotonic sample, after the realtime sample; the bound grows from `as_of` to it.
    mono: u64,
    offset_low: u64,
    offset_high: u64,
}

/// The suspend evidence of every bracket since construction: the latest bracket's upper bound on the boot offset, the earliest `as_of` that neither construction nor a detected suspend separates from now, and whether a suspend was detected.
#[derive(Debug, Clone, Copy)]
struct Chain {
    offset_high: u64,
    clean_since: u64,
    suspended: bool,
}

/// Why a reader cannot be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentV2Error {
    /// Returned on a 64-bit Linux architecture other than x86-64 and AArch64.
    UnsupportedTarget,
    ZeroReadAttempts,
    ZeroBracketLimit,
}

/// The reading logic over a [`Host`].
pub(crate) struct Reader<H> {
    host: H,
    scale: ClockScale,
    attempts: u32,
    bracket_limit_ns: u64,
    snapshot: Option<(u16, Body)>,
    chain: Option<Chain>,
}

impl<H: Host> Reader<H> {
    /// A reader on `scale` making at most `attempts` attempts a reading, whose suspend brackets admit at most `bracket_limit_ns` between their two monotonic samples; construction takes the first bracket.
    pub(crate) fn new(
        host: H,
        scale: ClockScale,
        attempts: u32,
        bracket_limit_ns: u64,
    ) -> Result<Self, SegmentV2Error> {
        if !cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
            return Err(SegmentV2Error::UnsupportedTarget);
        }
        if attempts == 0 {
            return Err(SegmentV2Error::ZeroReadAttempts);
        }
        if bracket_limit_ns == 0 {
            return Err(SegmentV2Error::ZeroBracketLimit);
        }
        let mut reader = Self {
            host,
            scale,
            attempts,
            bracket_limit_ns,
            snapshot: None,
            chain: None,
        };
        let _ = reader.clocks();
        Ok(reader)
    }

    #[cfg(test)]
    pub(crate) fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }

    pub(crate) fn read(&mut self) -> Reading {
        let mut short = false;
        let mut clocks = None;
        for _ in 0..self.attempts {
            match self.attempt() {
                Attempt::Fresh(generation, body) => {
                    self.snapshot = Some((generation, body));
                    if let Some(read) = self.clocks() {
                        clocks = Some(read);
                        break;
                    }
                }
                Attempt::Retry { short: failed } => short |= failed,
                Attempt::Refused(cause) => {
                    // A refused read is newer than the snapshot and yields no body, so no later reading trusts the older one.
                    self.snapshot = None;
                    return Reading::untrusted(cause);
                }
            }
        }
        let Some(snapshot) = self.snapshot else {
            return Reading::untrusted(if short {
                Untrusted::Missing
            } else {
                Untrusted::NoSnapshot
            });
        };
        let Some(clocks) = clocks.or_else(|| self.clocks()) else {
            return Reading::untrusted(Untrusted::UnboundedBracket);
        };
        match self.verdict(snapshot, &clocks) {
            Some(cause) => Reading::untrusted(cause),
            None => bounded(&snapshot.1, &clocks),
        }
    }

    /// Always inlined, as `order_loads` is, so both barriers land in the extent of the `inline(never)` caller the barrier scan inspects; `pub(super)` for that caller in the sibling barrier test module.
    #[inline(always)]
    pub(super) fn attempt(&mut self) -> Attempt {
        let mut first = [0; HEADER_LEN];
        let mut payload = [0; BODY_LEN];
        let mut last = [0; HEADER_LEN];
        let first_whole = self.host.segment(0, &mut first) == Some(HEADER_LEN);
        order_loads();
        let body_whole = self.host.segment(HEADER_LEN as u64, &mut payload) == Some(BODY_LEN);
        order_loads();
        let last_whole = self.host.segment(0, &mut last) == Some(HEADER_LEN);
        if !(first_whole && body_whole && last_whole) {
            return Attempt::Retry { short: true };
        }
        let (opened, closed) = match (header(&first), header(&last)) {
            (Header::Generation(opened), Header::Generation(closed)) => (opened, closed),
            (Header::Refused(cause), _) | (_, Header::Refused(cause)) => {
                return Attempt::Refused(cause);
            }
            _ => return Attempt::Retry { short: false },
        };
        if opened != closed || opened % 2 == 1 {
            return Attempt::Retry { short: false };
        }
        match body(&payload) {
            Ok(body) => Attempt::Fresh(opened, body),
            Err(cause) => Attempt::Refused(cause),
        }
    }

    /// The realtime sample and the suspend bracket after it, or `None` when a sample fails, the bracket is wider than the limit, or boot time reads below the first monotonic sample; a bracket whose lower bound exceeds the previous bracket's upper bound shows a suspend between them, after which only a snapshot written at or after this bracket is trusted.
    fn clocks(&mut self) -> Option<Clocks> {
        let real = self.host.clock(ClockId::Realtime)?;
        let mono = self.host.clock(ClockId::Monotonic)?;
        let boot = self.host.clock(ClockId::Boottime)?;
        let after = self.host.clock(ClockId::Monotonic)?;
        if after.checked_sub(mono)? > self.bracket_limit_ns {
            return None;
        }
        let clocks = Clocks {
            real,
            mono,
            // The boot offset is nonnegative, so saturating `boot - after` at zero keeps a lower bound when the read gap exceeds the offset, as on a host that never suspended.
            offset_low: boot.saturating_sub(after),
            offset_high: boot.checked_sub(mono)?,
        };
        let (clean_since, suspended) = match self.chain {
            None => (after, false),
            Some(chain) if clocks.offset_low <= chain.offset_high => {
                (chain.clean_since, chain.suspended)
            }
            Some(_) => (after, true),
        };
        self.chain = Some(Chain {
            offset_high: clocks.offset_high,
            clean_since,
            suspended,
        });
        Some(clocks)
    }

    /// The first cause that leaves `snapshot` untrusted at `clocks`, in the order the module states.
    fn verdict(&mut self, snapshot: (u16, Body), clocks: &Clocks) -> Option<Untrusted> {
        let body = &snapshot.1;
        match body.status {
            SYNCHRONIZED | FREE_RUNNING => {}
            #[cfg(test)]
            DISRUPTED if super::plant::planted(super::plant::Plant::TrustDisrupted) => {}
            DISRUPTED => return Some(Untrusted::Disrupted),
            _ => return Some(Untrusted::Unknown),
        }
        // The coarse clock `as_of` was read on lags the fine one, so a fine sample below it breaks causality.
        if clocks.mono < body.as_of {
            return Some(Untrusted::Malformed);
        }
        if clocks.mono > body.void_after {
            return Some(Untrusted::Stale);
        }
        if !body.disruption_support {
            return Some(Untrusted::DisruptionSupportOff);
        }
        let mut marker = [0; MARKER_LEN];
        if self.host.marker(&mut marker) != Some(MARKER_LEN)
            || u32::from_le_bytes(field(&marker, 0)) != MARKER_MAGIC
        {
            return Some(Untrusted::MarkerUnavailable);
        }
        if u64::from_le_bytes(field(&marker, 16)) != body.marker {
            return Some(Untrusted::MarkerMismatch);
        }
        match self.chain {
            Some(chain) if body.as_of >= chain.clean_since => {}
            Some(chain) if chain.suspended => return Some(Untrusted::Suspended),
            _ => return Some(Untrusted::NoWriterUpdate),
        }
        (!self.host.writer_stores_ordered()).then_some(Untrusted::UnorderedWriter)
    }
}

/// The trusted reading around `clocks.real`: the snapshot's bound grown from `as_of` to the monotonic sample after the realtime one by the drift rate, rounded up; `Malformed` when the bound passes `u64`.
fn bounded(body: &Body, clocks: &Clocks) -> Reading {
    let elapsed = u128::from(clocks.mono - body.as_of);
    let grown = (elapsed * u128::from(body.drift_ppb)).div_ceil(u128::from(NANOS_PER_SECOND));
    // The drift rate is below one part per one, so the growth is below the elapsed time and fits.
    match body
        .bound
        .checked_add(grown as u64)
        .and_then(|bound| Some((bound, clocks.real.checked_add(bound)?)))
    {
        Some((bound, latest)) => Reading {
            earliest: clocks.real.saturating_sub(bound),
            latest,
            trust: Trust::Trusted,
        },
        None => Reading::untrusted(Untrusted::Malformed),
    }
}

/// The host's segment and marker files, each opened once, and its clocks.
pub(crate) struct LinuxHost {
    segment: Option<File>,
    marker: Option<File>,
}

impl Host for LinuxHost {
    fn segment(&mut self, at: u64, bytes: &mut [u8]) -> Option<usize> {
        super::super::os::read_at(self.segment.as_ref()?, bytes, at)
    }

    fn marker(&mut self, bytes: &mut [u8]) -> Option<usize> {
        super::super::os::read_at(self.marker.as_ref()?, bytes, 0)
    }

    fn clock(&mut self, clock: ClockId) -> Option<u64> {
        super::super::os::clock_ticks(match clock {
            ClockId::Realtime => libc::CLOCK_REALTIME,
            ClockId::Monotonic => libc::CLOCK_MONOTONIC,
            ClockId::Boottime => libc::CLOCK_BOOTTIME,
        })
    }

    fn writer_stores_ordered(&self) -> bool {
        cfg!(target_arch = "x86_64")
    }
}

/// The production provider over the protocol v2 segment at one path and the marker device at another.
pub struct SegmentV2(Reader<LinuxHost>);

impl SegmentV2 {
    /// Opens `segment` and `marker` once and takes the first suspend bracket; a file that cannot be opened stays absent for the reader's life, so every reading reports it untrusted, which requires the daemon to start before the reader.
    ///
    /// The segment opens with `O_NOATIME`, which suppresses access-time updates on its reads; when that open fails, as it does for a caller that neither owns the file nor holds `CAP_FOWNER`, the reader opens it with `File::open`.
    ///
    /// `scale` is the scale the host's realtime clock follows, `read_attempts` the attempts a reading makes, and `bracket_limit_ns` the widest suspend bracket an attempt admits.
    pub fn open(
        segment: &Path,
        marker: &Path,
        scale: ClockScale,
        read_attempts: u32,
        bracket_limit_ns: u64,
    ) -> Result<Self, SegmentV2Error> {
        let host = LinuxHost {
            segment: OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOATIME)
                .open(segment)
                .or_else(|_| File::open(segment))
                .ok(),
            marker: File::open(marker).ok(),
        };
        Reader::new(host, scale, read_attempts, bracket_limit_ns).map(Self)
    }
}

impl super::clock::sealed::Sealed for SegmentV2 {}

impl PhysicalClock for SegmentV2 {
    fn scale(&self) -> ClockScale {
        self.0.scale
    }

    fn read(&mut self) -> Reading {
        self.0.read()
    }
}
