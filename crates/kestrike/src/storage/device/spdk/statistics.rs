//! The EBS statistics log page, its parser, and the handle that asks the SPDK driver for it.
//!
//! - The page is log page [`LOG_PAGE`], [`PAGE_LEN`] little-endian bytes that open with the EBS magic; its counters accumulate, and `queue_length` reports the current queue length.
//! - [`parse`] reads the page's fixed offsets and refuses a page whose magic differs or whose histogram names more than [`HISTOGRAM_BINS`] bins.
//! - [`StatisticsHandle::request`] sets a flag that a running driver's service call reads once no log-page command is outstanding; that call submits the command or publishes SPDK's refusal, the service call during which the command's callback runs publishes the reading, and every native call runs on the driver's thread.
//! - A stopping or gone driver publishes [`StatisticsFailure::DeviceGone`] at its next service call for the command outstanding or the request pending at that call. A quiesce returning `Stopped` publishes `DeviceGone` at once, and later requests publish it inside [`StatisticsHandle::request`].

use std::sync::Arc;
#[cfg(not(all(test, loom)))]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
#[cfg(not(all(test, loom)))]
use std::sync::{Mutex, MutexGuard};

#[cfg(all(test, loom))]
use loom::sync::MutexGuard;
#[cfg(all(test, loom))]
use statistics_model::{Flag as AtomicBool, Lock as Mutex};

#[cfg(all(test, loom))]
mod statistics_model;

pub(super) const LOG_PAGE: u8 = 0xD0;
pub(super) const PAGE_LEN: usize = 4096;
const MAGIC: u32 = 0x3C23_B510;
pub const HISTOGRAM_BINS: usize = 64;
const READ_HISTOGRAM_AT: usize = 512;
const BIN_LEN: usize = 24;
const WRITE_HISTOGRAM_AT: usize = READ_HISTOGRAM_AT + 8 + HISTOGRAM_BINS * BIN_LEN;

/// Operations whose latency fell between `lower_us` and `upper_us`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LatencyBin {
    pub lower_us: u64,
    pub upper_us: u64,
    pub count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatencyHistogram {
    bins: [LatencyBin; HISTOGRAM_BINS],
    len: usize,
}

impl LatencyHistogram {
    /// The bins the device filled, in page order.
    pub fn bins(&self) -> &[LatencyBin] {
        &self.bins[..self.len]
    }
}

/// The counters of one page; each `_us` field counts microseconds, and the `exceeded` fields count the time the volume's or the instance's EBS limit held I/O back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbsStatistics {
    pub read_ops: u64,
    pub write_ops: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_time_us: u64,
    pub write_time_us: u64,
    pub volume_exceeded_iops_us: u64,
    pub volume_exceeded_throughput_us: u64,
    pub instance_exceeded_iops_us: u64,
    pub instance_exceeded_throughput_us: u64,
    pub queue_length: u64,
    pub read_latency: LatencyHistogram,
    pub write_latency: LatencyHistogram,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatisticsError {
    /// The page opens with this value in place of the EBS magic.
    Magic(u32),
    /// A histogram names this many bins, above [`HISTOGRAM_BINS`].
    Bins(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatisticsFailure {
    /// SPDK refused the command with this return code.
    Refused(i32),
    /// The command completed with this raw NVMe status word.
    Status(u16),
    Parse(StatisticsError),
    DeviceGone(Option<i32>),
}

/// One published reading; `sequence` counts the driver's published readings, the first one 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
    pub sequence: u64,
    pub outcome: Result<EbsStatistics, StatisticsFailure>,
}

fn u32_at(page: &[u8; PAGE_LEN], at: usize) -> u32 {
    let mut word = [0; 4];
    word.copy_from_slice(&page[at..at + 4]);
    u32::from_le_bytes(word)
}

fn u64_at(page: &[u8; PAGE_LEN], at: usize) -> u64 {
    let mut word = [0; 8];
    word.copy_from_slice(&page[at..at + 8]);
    u64::from_le_bytes(word)
}

fn histogram(page: &[u8; PAGE_LEN], at: usize) -> Result<LatencyHistogram, StatisticsError> {
    let count = u64_at(page, at);
    let len = usize::try_from(count)
        .ok()
        .filter(|&len| len <= HISTOGRAM_BINS)
        .ok_or(StatisticsError::Bins(count))?;
    let mut bins = [LatencyBin::default(); HISTOGRAM_BINS];
    for (index, bin) in bins.iter_mut().enumerate().take(len) {
        let base = at + 8 + index * BIN_LEN;
        *bin = LatencyBin {
            lower_us: u64_at(page, base),
            upper_us: u64_at(page, base + 8),
            count: u32_at(page, base + 16),
        };
    }
    Ok(LatencyHistogram { bins, len })
}

/// Parses one EBS statistics page.
///
/// # Errors
///
/// `Magic` when the page's first word is not the EBS magic, then `Bins` for the read histogram, then for the write histogram.
pub fn parse(page: &[u8; PAGE_LEN]) -> Result<EbsStatistics, StatisticsError> {
    let magic = u32_at(page, 0);
    if magic != MAGIC {
        return Err(StatisticsError::Magic(magic));
    }
    let field = |index: usize| u64_at(page, 8 + 8 * index);
    Ok(EbsStatistics {
        read_ops: field(0),
        write_ops: field(1),
        read_bytes: field(2),
        write_bytes: field(3),
        read_time_us: field(4),
        write_time_us: field(5),
        volume_exceeded_iops_us: field(6),
        volume_exceeded_throughput_us: field(7),
        instance_exceeded_iops_us: field(8),
        instance_exceeded_throughput_us: field(9),
        queue_length: field(10),
        read_latency: histogram(page, READ_HISTOGRAM_AT)?,
        write_latency: histogram(page, WRITE_HISTOGRAM_AT)?,
    })
}

/// The request flag and the latest reading, shared by the driver and its handles.
#[derive(Debug, Default)]
pub(super) struct Shared {
    requested: AtomicBool,
    latest: Mutex<Published>,
}

#[derive(Debug, Default)]
struct Published {
    reading: Option<Reading>,
    /// When set, [`StatisticsHandle::request`] publishes `DeviceGone` for the pending request it consumes.
    stopped: bool,
}

impl Published {
    fn push(&mut self, outcome: Result<EbsStatistics, StatisticsFailure>) {
        let sequence = self.reading.map_or(1, |reading| reading.sequence + 1);
        self.reading = Some(Reading { sequence, outcome });
    }
}

impl Shared {
    fn latest(&self) -> MutexGuard<'_, Published> {
        self.latest
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Consumes a pending request. A call with no request pending costs one relaxed load, because the swap runs only after the load saw the flag set. The `latest` mutex orders every published reading, so relaxed ordering suffices for `requested`.
    pub(super) fn take_request(&self) -> bool {
        self.requested.load(Ordering::Relaxed) && self.requested.swap(false, Ordering::Relaxed)
    }

    /// Publishes the outcome of the next request in sequence.
    pub(super) fn publish(&self, outcome: Result<EbsStatistics, StatisticsFailure>) {
        self.latest().push(outcome);
    }

    /// Sets the stop mark and publishes `DeviceGone` for a pending request.
    /// The mark and [`StatisticsHandle::request`]'s check both run under the `latest` mutex, so a request either finds the mark or sets its flag before this call consumes it.
    pub(super) fn stop(&self) {
        let mut latest = self.latest();
        latest.stopped = true;
        if self.take_request() {
            latest.push(Err(StatisticsFailure::DeviceGone(None)));
        }
    }
}

/// A `Send` and `Sync` handle to one driver's statistics: any thread may request a reading and read the latest one.
#[derive(Debug, Clone)]
pub struct StatisticsHandle(pub(super) Arc<Shared>);

impl StatisticsHandle {
    /// Asks for a reading. Requests coalesce: a running driver submits one log-page command at its first service call with no command outstanding, and that command's reading answers every request made before that call.
    /// After `Shared::stop` sets `stopped`, this call publishes `DeviceGone` for the pending request it consumes.
    pub fn request(&self) {
        self.0.requested.store(true, Ordering::Relaxed);
        let mut latest = self.0.latest();
        if latest.stopped && self.0.take_request() {
            latest.push(Err(StatisticsFailure::DeviceGone(None)));
        }
    }

    pub fn latest(&self) -> Option<Reading> {
        self.0.latest().reading
    }
}
