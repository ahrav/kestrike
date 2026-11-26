//! A fill decides admission after it holds fill authority and knows the candidate's bounded metadata and body lengths, and before it reserves payload.
//! A refusal never removes a proposed resident victim; the caller terminates only its own attempt.
//! The admit-all control keeps no state, spends no budget and adds nothing to the engine ledger.
//! `Admit` grants no reservation, publication authority or freshness; the reservation that follows applies its own cutoff, gate, extent and slot checks.

use super::layout::{LayoutError, ObjectGeometry, object_geometry};
use super::os::Platform;
use super::owner::Storage;
use super::record::ValidRecordConfig;

/// `Ineligible` identifies why a candidate cannot occupy resident storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ineligible {
    /// The storage is drained.
    TornDown,
    /// An unknown length, a length over its cap, or an overflowing length
    /// makes the candidate ineligible.
    Layout(LayoutError),
}

/// Holds reservation inputs; constructing `Admitted` does not reserve capacity.
///
/// Only [`Storage::decide_admission`] constructs one, after the storage's caps accept both lengths, so `metadata_len + body_len` is within the object limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admitted {
    /// The record format of the storage that decided.
    record: ValidRecordConfig,
    metadata_len: usize,
    body_len: usize,
}

impl Admitted {
    /// Extents the object needs, at least one.
    #[inline]
    pub fn extents(&self) -> u32 {
        let len = self.metadata_len as u64 + self.body_len as u64;
        ObjectGeometry::new(len, &self.record)
            .expect("an admitted object is within the object limit")
            .extents()
    }

    /// Whether `self` was decided for these lengths under this record format.
    /// An object's geometry is a function of its payload length and the record format, so a decision that passes was made for the geometry the caller derives from the same lengths under `record`.
    pub(super) fn describes(
        &self,
        metadata_len: usize,
        body_len: usize,
        record: &ValidRecordConfig,
    ) -> bool {
        self.metadata_len == metadata_len && self.body_len == body_len && self.record == *record
    }
}

/// The outcome of one [`Storage::decide_admission`] call; the caller keeps it for the life of its attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "handle the decision before reserving payload; an Admit reserves nothing"]
pub enum Decision {
    /// The candidate is eligible and the control admits it; nothing is reserved.
    Admit(Admitted),
    /// The candidate cannot occupy resident storage, whatever the control would say.
    Ineligible(Ineligible),
    /// Admission is closed: the cutoff read `true`.
    Closed,
}

impl<P: Platform> Storage<P> {
    /// `None` is an unknown length, not zero. `Admit` claims no extent, slot or index entry and grants no publication authority or freshness; the reservation that follows applies its own cutoff, gate, extent and slot checks and may still refuse.
    /// A candidate refused for its layout stays `Ineligible` after close, because that check precedes the cutoff read; the cutoff read is one `SeqCst` observation, not a promise that the storage stays open until the reservation.
    /// Validation bounds every admissible layout inside an empty volume, so the decision spends no budget.
    // Inlining lets callers optimize the aggregate decision together with
    // their outcome handling.
    #[inline(always)]
    pub fn decide_admission(
        &self,
        metadata_len: Option<usize>,
        body_len: Option<usize>,
    ) -> Decision {
        let Some(root) = self.root() else {
            return Decision::Ineligible(Ineligible::TornDown);
        };
        if let Err(reason) = object_geometry(
            metadata_len,
            body_len,
            root.metadata_cap,
            root.body_cap,
            &self.record,
        ) {
            return Decision::Ineligible(Ineligible::Layout(reason));
        }
        if self.is_closed() {
            return Decision::Closed;
        }
        // The geometry accepted both lengths, so both are known.
        Decision::Admit(Admitted {
            record: self.record,
            metadata_len: metadata_len.unwrap_or_default(),
            body_len: body_len.unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::budget::WorkBudget;
    use super::super::config::StorageConfig;
    use super::super::geometry::EXTENT_PAYLOAD;
    use super::super::layout::{IO_UNIT, LayoutError};
    use super::super::owner::{PoolReport, Storage};
    use super::super::placement::PlacementConfig;
    use super::super::reserve::ReserveError;
    use super::super::tables::{SlotIndex, SlotState};
    use super::super::test_platform::TestPlatform;
    use super::super::{lookup_tests, publish_tests};
    use super::{Admitted, Decision, Ineligible};

    const PAGE: usize = 4096;
    const SLOTS: usize = 4;
    const UNITS: usize = 5;
    const METADATA_CAP: usize = 64;
    const BODY_CAP: usize = 2 * IO_UNIT;
    /// Each candidate specifies metadata bytes, body bytes, and expected
    /// record units.
    const CANDIDATES: [(usize, usize, usize); 6] = [
        (1, 1, 1),
        (0, 0, 1),
        (1, IO_UNIT - 117, 1),
        (1, IO_UNIT - 116, 2),
        (METADATA_CAP, IO_UNIT, 2),
        (METADATA_CAP, BODY_CAP, 3),
    ];

    fn config() -> StorageConfig {
        StorageConfig {
            page_size: PAGE,
            engine_budget: 1 << 24,
            body_cap: BODY_CAP,
            metadata_cap: Some(METADATA_CAP),
            lease_limit: 1024,
            object_rights: 64,
            reader_limit: 4,
            volume: crate::storage::test_volume(UNITS * IO_UNIT, SLOTS),
        }
    }

    fn storage() -> Storage<TestPlatform> {
        Storage::initialize(
            &config().validate().unwrap(),
            &PlacementConfig { control_home: 0 },
            TestPlatform::heap(PAGE),
        )
        .unwrap()
    }

    /// Enough for a reservation: the gate try, the update, one slot take's
    /// bundle and the extent search.
    fn budget() -> WorkBudget {
        WorkBudget::new(1 << 10)
    }

    fn admitted(decision: Decision) -> Admitted {
        match decision {
            Decision::Admit(admitted) => admitted,
            other => panic!("expected Admit, got {other:?}"),
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Snapshot {
        engine_used: usize,
        pool: Option<PoolReport>,
        slots: Vec<Option<(SlotState, u32)>>,
    }

    fn snapshot(storage: &Storage<TestPlatform>) -> Snapshot {
        let report = storage.pool_report().unwrap();
        Snapshot {
            engine_used: storage.engine_used(),
            pool: Some(report),
            slots: (0..report.descriptor.slot_count)
                .map(|slot| storage.slot_state(SlotIndex(slot)))
                .collect(),
        }
    }

    /// Each candidate admits as one extent, and the validated configuration's
    /// layout and the reservation's locator each charge the table's units.
    #[test]
    fn every_admissible_candidate_admits_as_one_extent_and_reserves_its_layout_s_units() {
        let storage = storage();
        let validated = config().validate().unwrap();
        for (metadata_len, body_len, units) in CANDIDATES {
            let admitted = admitted(storage.decide_admission(Some(metadata_len), Some(body_len)));
            let layout = validated
                .layout(Some(metadata_len), Some(body_len))
                .unwrap();
            assert_eq!((admitted.extents(), layout.units()), (1, units));
            let allocation = storage
                .reserve(Some(metadata_len), Some(body_len), &mut budget())
                .unwrap();
            assert_eq!(allocation.locator().len_units() as usize, units);
            assert_eq!(allocation.layout().metadata_len(), metadata_len);
            assert_eq!(allocation.layout().body_len(), body_len);
            assert_eq!(allocation.cancel(), Ok(()));
        }
    }

    /// The extent count follows the summed length across each extent
    /// boundary, whichever of the two lengths carries the bytes.
    #[test]
    fn a_decision_counts_the_extents_of_the_summed_lengths() {
        const P: usize = EXTENT_PAYLOAD as usize;
        let config = StorageConfig {
            body_cap: 3 * P,
            volume: crate::storage::test_volume(256 * IO_UNIT, SLOTS),
            ..config()
        };
        let storage = Storage::initialize(
            &config.validate().unwrap(),
            &PlacementConfig { control_home: 0 },
            TestPlatform::heap(PAGE),
        )
        .unwrap();
        for (metadata_len, body_len, extents) in [
            (0, 0, 1),
            (0, P, 1),
            (METADATA_CAP, P - METADATA_CAP, 1),
            (METADATA_CAP, P - METADATA_CAP + 1, 2),
            (0, P + 1, 2),
            (0, 2 * P, 2),
            (1, 2 * P, 3),
            (0, 3 * P, 3),
            (1, 3 * P, 4),
        ] {
            let admitted = admitted(storage.decide_admission(Some(metadata_len), Some(body_len)));
            assert_eq!(admitted.extents(), extents, "{metadata_len} {body_len}");
        }
    }

    #[test]
    fn each_ineligible_candidate_names_its_own_reason() {
        let storage = storage();
        let before = snapshot(&storage);
        let cases = [
            (None, Some(1), LayoutError::UnknownLength),
            (Some(1), None, LayoutError::UnknownLength),
            (
                Some(METADATA_CAP + 1),
                Some(1),
                LayoutError::MetadataTooLarge {
                    len: METADATA_CAP + 1,
                    cap: METADATA_CAP,
                },
            ),
            (
                Some(1),
                Some(BODY_CAP + 1),
                LayoutError::BodyTooLarge {
                    len: BODY_CAP + 1,
                    cap: BODY_CAP,
                },
            ),
            (
                Some(METADATA_CAP + 1),
                Some(BODY_CAP + 1),
                LayoutError::MetadataTooLarge {
                    len: METADATA_CAP + 1,
                    cap: METADATA_CAP,
                },
            ),
        ];
        let mut zero = WorkBudget::new(0);
        for (metadata_len, body_len, reason) in cases {
            let allocations = crate::instrument::allocations();
            assert_eq!(
                storage.decide_admission(metadata_len, body_len),
                Decision::Ineligible(Ineligible::Layout(reason))
            );
            assert_eq!(crate::instrument::allocations(), allocations);
            assert_eq!(
                storage.reserve(metadata_len, body_len, &mut zero).err(),
                Some(ReserveError::Layout(reason))
            );
        }
        assert_eq!(zero.counters(), Default::default());
        assert_eq!(snapshot(&storage), before);
    }

    #[test]
    fn a_decision_after_close_is_closed_and_an_earlier_admit_does_not_pass_the_reservation() {
        let storage = storage();
        let before = snapshot(&storage);
        let _ = admitted(storage.decide_admission(Some(1), Some(1)));
        storage.close();
        assert_eq!(storage.decide_admission(Some(1), Some(1)), Decision::Closed);
        assert_eq!(
            storage.decide_admission(None, Some(1)),
            Decision::Ineligible(Ineligible::Layout(LayoutError::UnknownLength))
        );
        assert_eq!(
            storage.reserve(Some(1), Some(1), &mut budget()).err(),
            Some(ReserveError::Closed)
        );
        assert_eq!(snapshot(&storage), before);
    }

    #[test]
    fn admission_manufactures_no_capacity_a_full_volume_still_refuses_the_reservation() {
        let storage = storage();
        let largest = storage
            .reserve(Some(METADATA_CAP), Some(BODY_CAP), &mut budget())
            .unwrap();
        let before = snapshot(&storage);
        let _ = admitted(storage.decide_admission(Some(METADATA_CAP), Some(BODY_CAP)));
        assert_eq!(snapshot(&storage), before);
        assert_eq!(
            storage
                .reserve(Some(METADATA_CAP), Some(BODY_CAP), &mut budget())
                .err(),
            Some(ReserveError::CleanReserve)
        );
        let after = snapshot(&storage);
        assert_eq!(after.pool, before.pool);
        assert_eq!(after.engine_used, before.engine_used);
        let small = storage.reserve(Some(1), Some(1), &mut budget()).unwrap();
        drop((largest, small));
    }

    #[test]
    fn no_outcome_changes_the_engine_the_volume_the_index_or_an_incumbent() {
        let storage = lookup_tests::ready(8);
        let key = publish_tests::key(0x21);
        let incumbent = publish_tests::completed(&storage, key)
            .publish(publish_tests::TRIES, &mut publish_tests::budget())
            .unwrap();
        let mut reader = storage.register().unwrap();
        lookup_tests::ticks(&storage, &[Some(1)]);
        let lease = lookup_tests::lookup(&mut reader, &key, publish_tests::RETRIES).unwrap();
        let before = snapshot(&storage);
        let shard = publish_tests::report(&storage, 0);
        let refs = publish_tests::refs(&storage, incumbent);
        let unchanged = |storage: &Storage<TestPlatform>| {
            assert_eq!(snapshot(storage), before);
            assert_eq!(publish_tests::report(storage, 0), shard);
            assert_eq!(publish_tests::refs(storage, incumbent), refs);
            assert!(storage.identity_is_current(incumbent));
            assert_eq!(lease.id(), incumbent);
        };
        let Decision::Admit(admitted) = storage.decide_admission(Some(4), Some(20)) else {
            panic!("an eligible candidate refused");
        };
        let outcomes = [
            ((Some(4), Some(20)), Decision::Admit(admitted)),
            (
                (None, Some(20)),
                Decision::Ineligible(Ineligible::Layout(LayoutError::UnknownLength)),
            ),
            (
                (Some(17), Some(20)),
                Decision::Ineligible(Ineligible::Layout(LayoutError::MetadataTooLarge {
                    len: 17,
                    cap: 16,
                })),
            ),
        ];
        for ((metadata_len, body_len), expected) in outcomes {
            let allocations = crate::instrument::allocations();
            assert_eq!(storage.decide_admission(metadata_len, body_len), expected);
            assert_eq!(crate::instrument::allocations(), allocations);
            unchanged(&storage);
            assert_eq!(publish_tests::candidates(&storage, &key), [incumbent]);
        }
        storage.close();
        assert_eq!(
            storage.decide_admission(Some(4), Some(20)),
            Decision::Closed
        );
        unchanged(&storage);
    }
}
