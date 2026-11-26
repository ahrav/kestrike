//! The volume's physical-clock provider on the publication path: one provider reading and then one monotonic sample, taken outside every gate and shared by the publications of the next [`PAIR_NS`] monotonic nanoseconds, whether the reading converts or not, converted into the portable pair `bind` stores, with the absent pairs counted by cause and the provider's trust state and last trusted sample kept as the report the volume copies out.

use super::super::device::Disk;
use super::super::os::Platform;
#[cfg(test)]
use super::super::portable::plant::{Plant, planted};
use super::super::portable::{ClockReport, PhysicalClock, PortableExpiry, Reading, Trust};
use super::super::slot::deadline_seconds;
use super::attach::Volume;

/// Monotonic nanoseconds a provider reading and its sample serve publications. A publication's lifetime shortens by the clock contract's rate bound times the pair's age, at the full age one nanosecond for each part per million of the bound.
const PAIR_NS: u64 = 1_000_000;

/// The provider and what its readings showed.
pub(super) struct Clock {
    provider: Box<dyn PhysicalClock>,
    /// The latest provider reading and the monotonic sample after it; `None` until the first publication.
    /// EXPIRY-SHORTENS holds for every deadline converted from a pair whose reading precedes its sample, so a pair serves each publication made within [`PAIR_NS`] of its sample. A reading that converts to no pair, such as one its provider reports untrusted, yields the same absence for each of those publications, so they share it too: publications read the provider at most once in each [`PAIR_NS`] of the monotonic clock while its samples succeed.
    pair: Option<(Reading, Option<u64>)>,
    pub(super) report: ClockReport,
}

impl Clock {
    pub(super) fn new(provider: Box<dyn PhysicalClock>) -> Self {
        Self {
            provider,
            pair: None,
            report: ClockReport::default(),
        }
    }

    /// When present, `after` must be a monotonic sample taken after `reading`.
    fn note(&mut self, reading: &Reading, after: Option<u64>) {
        self.report.trust = Some(reading.trust);
        if reading.trust == Trust::Trusted && after.is_some() {
            self.report.last_trusted_at = after;
        }
    }
}

impl<P: Platform, D: Disk> Volume<'_, '_, P, D> {
    /// The portable pair of a publication whose live deadline is `expires_at_ticks`, converted under the storage's clock contract from the latest provider reading and the monotonic sample after it, or [`PortableExpiry::ABSENT`] with its cause counted once. The volume takes a new reading and sample here unless it holds a reading whose sample the monotonic clock reads less than [`PAIR_NS`] past; a reading whose conversion fails stays held on the same terms.
    pub(crate) fn portable_expiry(&mut self, expires_at_ticks: u64) -> PortableExpiry {
        let (reading, sample) = match self.clock.pair.filter(|pair| self.pair_serves(pair)) {
            Some(pair) => pair,
            None => {
                let pair = self.sample_clock();
                self.clock.pair = Some(pair);
                pair
            }
        };
        self.clock.note(&reading, sample);
        let contract = self.storage.clock;
        #[cfg(test)]
        let contract = if planted(Plant::IgnoreRateBound) {
            super::super::portable::ClockContract {
                rate_error_ppb: 0,
                ..contract
            }
        } else {
            contract
        };
        let live_s = deadline_seconds(expires_at_ticks);
        match PortableExpiry::of(&reading, &contract, sample, live_s) {
            #[cfg(test)]
            Ok(expiry) if planted(Plant::ClampAsNever) && expiry.lifetime_ms == u32::MAX => {
                PortableExpiry {
                    deadline_ns: u64::MAX,
                    ..expiry
                }
            }
            Ok(expiry) => expiry,
            Err(cause) => {
                self.clock.report.absent.count(cause);
                PortableExpiry::ABSENT
            }
        }
    }

    /// Sampling before the provider reading keeps a recovered deadline's start at or before the reading's physical instant.
    pub(super) fn recovery_sample(&mut self) -> (Option<u64>, Reading) {
        let before = self.storage.platform.now_ticks();
        let reading = self.clock.provider.read();
        let after = self.storage.platform.now_ticks();
        self.clock.note(&reading, after);
        (before, reading)
    }

    /// Whether `pair` serves a publication made now: its sample is present and the monotonic clock reads less than [`PAIR_NS`] past it.
    fn pair_serves(&self, pair: &(Reading, Option<u64>)) -> bool {
        pair.1.is_some_and(|sample| {
            self.storage
                .platform
                .now_ticks()
                .and_then(|now| now.checked_sub(sample))
                .is_some_and(|age| age < PAIR_NS)
        })
    }

    /// The provider's reading and the monotonic sample after it.
    fn sample_clock(&mut self) -> (Reading, Option<u64>) {
        #[cfg(test)]
        if planted(Plant::SamplingOrder) {
            let sample = self.storage.platform.now_ticks();
            return (self.clock.provider.read(), sample);
        }
        let reading = self.clock.provider.read();
        (reading, self.storage.platform.now_ticks())
    }
}
