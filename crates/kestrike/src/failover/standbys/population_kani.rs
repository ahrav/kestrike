//! Kani proof of the standby population's decisions: [`need`](super::need),
//! [`Population::admit`](super::Population::admit), [`Census::released`](super::Census::released) and
//! [`Census::pending`](super::Census::pending).
//!
//! - HOST-LOSS-KEEPS-VOLUME: a shard needs something only at `E > 0` with no standby or one the caller's evidence
//!   shows lost, and the need is a designation: a fresh host when the evidence shows the owner lost, and otherwise a
//!   standby. `Standby` reads only that the evidence does not show the owner lost; the planner's own `Live` check
//!   establishes a live owner.
//! - POPULATION-CAP: an admission that adds a shard leaves at most `min(cap, MAX_SLOTS)` entries, and one that
//!   updates a listed shard keeps the entry count.
//! - An admission writes the record's `(g, owner, E)` and the candidate into the shard's slot at its ascending place,
//!   keeps the zone and every other entry in order, frames the result with its entry count and byte length, and sets
//!   the census's sound flag, which the store client's lend reads, exactly when the record's `E` is in
//!   `1..=ATTEMPTS_MAX`; a release removes only the record's entry, keeps the zone and every other entry in order, and
//!   frames the result the same way.
//! - ONE-HOST-PER-SLOT, FEASIBLE-SLOT, HEADROOM: the admission refuses in the order `Ineligible`, `Closed`,
//!   `Headroom`, `Taken`, `Full`, each on exactly its condition, and returns `None` for a slot the census already
//!   lists for the candidate at the record's tenure.
//! - HEADROOM's pending count: an entry of a shard other than the record's counts against the candidate exactly when
//!   its host is the candidate's and the candidate's report lists that shard in no standby role.
//! - CENSUS-COVERS: a release drops an entry only when the record names no standby, holds another `(g, owner, E)`
//!   than the entry's, and the entry's host is the owner or shows no live attach.
//!
//! Bounds: each census proof runs over a census of one length in any zone, each entry any `(g, owner, E)` and host
//! the census decoder admits: the admission proofs over 0, 1, 2 and 3 entries and the release proofs over 1, 2 and
//! 3. An admission into two or three entries has one proof per place of the record's shard, which bounds each
//! proof's formula: each takes 1.8 to 2.5 GiB in CBMC. Those proofs fit in memory under the lane's CBMC argument
//! `--max-field-sensitivity-array-size 128`, which `verification/kani/expected.json` declares: by default CBMC tracks
//! the elements of an array one by one only in arrays of at most 64 elements, a census of two entries holds 66
//! bytes, and without the argument the listed shards and the place of the written row are unknowns of the formula,
//! which then passes 11 GiB in a proof within 97 s. These proofs allocate each census at its encoded length: a
//! three-entry census occupies 94 bytes, and admitting a fourth entry raises its length to 122 bytes, both within
//! CBMC's configured 128-element field-sensitivity limit for byte arrays.
//!
//! The admission into an empty census takes the record under any shard, and the release from one entry takes any
//! listed shard and the record under any shard. The other census proofs list the shards 2, 2^9 and 2^17, which
//! differ in three bytes, and the record's shard takes the value below the first, each listed shard and the value
//! just above each. The decisions read a shard only to order it against another and to write it into its row, so
//! these values realize every order of the record's shard among the census's, and with them every census of the
//! proof's length; that the decisions read shards only so is a premise those proofs do not check.
//!
//! The record is any value of every other field (`failover::symbolic_kani`); the candidate's attachment and recovery
//! gauges are each unavailable or any `used` and `limit`, its other gauges unavailable, and in the admission proofs
//! its report lists no volume; the pending-count proof lists two volume entries, each under any shard in any recorded
//! role, and checks the standby-role exemption of HEADROOM's pending count. Its control inverts the standby predicate
//! for each reported entry and covers counts above and below the reference. With at most three entries the pending
//! count reads one 64-row chunk and `cap`, any `usize`, always binds below `MAX_SLOTS`. The caller's loss and live-attach evidence is true at each of two symbolic
//! hosts and false elsewhere; an admission and a release consult it at most once, and `need` at the standby and the
//! owner. The census proofs unwind 30 iterations, which covers the 28-byte entry copy of the census splice and every
//! loop over a census of three entries; `need` calls no loop of its own, and its proof's only loops are the shard
//! record generator's `MAX_CHAIN` suffixes. The expected tenure of every oracle is the record's `generation`, `owner`
//! and `attempts` fields, written out in the harness.

#[cfg(kani)]
mod verification {
    use super::super::{
        Attach, CENSUS_ENTRY, CENSUS_FIXED, Census, Entry, MAX_SLOTS, Need, Population, Refusal,
        Zone, fields, need, row,
    };
    use crate::failover::records::{ATTEMPTS_MAX, Host, ShardRecord};
    use crate::failover::report::{
        Backlog, BuildIdentity, Captures, Coverage, Detector, Enumeration, Gauge, Headroom,
        HostReport, HostState, Members, Pressure, RecordedRole, Recovery, RecoveryIo,
        RecoveryTimes, StoreOutcomes, VolumeEntry, Watermark, WriterId,
    };
    use crate::failover::retire::Target;
    use crate::failover::symbolic_kani::values::{host, shard, shard_record, target, volume};
    use crate::net::ownership::Shard;

    /// The most entries a census of these proofs holds.
    const ENTRIES: usize = 3;

    /// The shard values the record's slot takes over a census of `N` entries: the value below the first listed
    /// shard, then each listed shard and the value just above it, `2N + 1` values.
    fn places<const N: usize>() -> impl Iterator<Item = u32> {
        (0..=2 * N as u32).map(|at| match at {
            0 => 1,
            _ => shard_at((at as usize - 1) / 2).get() + (at - 1) % 2,
        })
    }

    /// A caller's evidence about hosts: true at each of two symbolic hosts, when present, and false at every other.
    #[derive(Clone, Copy)]
    struct Evidence(Option<Host>, Option<Host>);

    impl Evidence {
        fn any() -> Self {
            Self(
                kani::any::<bool>().then(host),
                kani::any::<bool>().then(host),
            )
        }

        fn holds(self, h: Host) -> bool {
            Some(h) == self.0 || Some(h) == self.1
        }
    }

    /// The census shard at index `at`: 2, 2^9 or 2^17.
    fn shard_at(at: usize) -> Shard {
        Shard::new(2 << (8 * at)).unwrap()
    }

    /// `ENTRIES` entries the census decoder admits: each host other than its tenure's owner, and `E` in
    /// `1..=ATTEMPTS_MAX`.
    fn entries() -> [Entry; ENTRIES] {
        let entries: [Entry; ENTRIES] = core::array::from_fn(|_| Entry {
            target: target(),
            host: host(),
        });
        for entry in entries {
            kani::assume(entry.host != entry.target.owner);
            kani::assume((1..=ATTEMPTS_MAX).contains(&entry.target.attempts));
        }
        entries
    }

    /// The shards [`shard_at`] names, in census order.
    fn fixed_shards() -> [Shard; ENTRIES] {
        core::array::from_fn(shard_at)
    }

    /// The census of `zone` that lists the first `N` of `entries`, each for its shard of `shards`, in a buffer
    /// allocated at exactly its encoded length. A buffer grown from `Census::empty` doubles its capacity, to 152
    /// bytes at three entries; at its length the census and the census one admission makes of it, at most four
    /// entries in 122 bytes, each stay within the array size the declared CBMC argument names.
    fn census<const N: usize>(
        zone: Zone,
        shards: &[Shard; ENTRIES],
        entries: &[Entry; ENTRIES],
    ) -> Census {
        let mut bytes = Vec::with_capacity(CENSUS_FIXED + N * CENSUS_ENTRY);
        bytes.extend_from_slice(&Census::empty(zone).bytes);
        bytes[CENSUS_FIXED - 2..].copy_from_slice(&(N as u16).to_be_bytes());
        for at in 0..N {
            bytes.extend_from_slice(&row(shards[at], entries[at]));
        }
        Census { bytes, sound: true }
    }

    /// The index the census of the first `N` entries gives `shard`, and the entry it lists there for `shard`.
    fn slot<const N: usize>(
        shards: &[Shard; ENTRIES],
        entries: &[Entry; ENTRIES],
        shard: Shard,
    ) -> (usize, Option<Entry>) {
        let place = (0..N).filter(|&at| shards[at] < shard).count();
        let held = (place < N && shards[place] == shard).then(|| entries[place]);
        (place, held)
    }

    fn gauge() -> Gauge {
        match kani::any() {
            true => Gauge::Known {
                used: kani::any(),
                limit: kani::any(),
            },
            false => Gauge::Unavailable,
        }
    }

    fn candidate() -> HostReport {
        HostReport {
            writer: WriterId {
                host: host(),
                boot: kani::any(),
            },
            sequence: kani::any(),
            sealed_at_us: kani::any(),
            host: HostState {
                build: BuildIdentity {
                    era: kani::any(),
                    digest: None,
                },
                headroom: Headroom {
                    ram: Gauge::Unavailable,
                    cpu_load: Gauge::Unavailable,
                    iops: Gauge::Unavailable,
                    bandwidth: Gauge::Unavailable,
                    attachments: gauge(),
                    workers: Gauge::Unavailable,
                    recovery: gauge(),
                },
                health: None,
                detector: Detector {
                    peers: Members::Unavailable,
                    self_suspect_us: None,
                    nominations: None,
                },
                producer_missing: Members::Unavailable,
                recovery_io: Gauge::Unavailable,
            },
            entries: Vec::new(),
        }
    }

    fn attach() -> Attach {
        let attach = match kani::any::<u8>() % 3 {
            0 => Attach::Live,
            1 => Attach::Open,
            _ => Attach::Closed,
        };
        // A new variant fails to compile here; the selector above then needs an arm for it.
        match attach {
            Attach::Live | Attach::Open | Attach::Closed => attach,
        }
    }

    /// The record's tenure `(g, owner, E)`, read from its fields.
    fn tenure(record: &ShardRecord) -> Target {
        Target {
            generation: record.generation,
            owner: record.owner,
            attempts: record.attempts,
        }
    }

    /// Asserts that `census` frames `rows` entries: its count field and its byte length both name `rows`.
    fn framed(census: &Census, rows: usize) {
        let count = u16::from_be_bytes([
            census.bytes[CENSUS_FIXED - 2],
            census.bytes[CENSUS_FIXED - 1],
        ]);
        assert_eq!(usize::from(count), rows);
        assert_eq!(census.bytes.len(), CENSUS_FIXED + rows * CENSUS_ENTRY);
    }

    /// The fields of the row `census` holds at index `at`, `None` past its end.
    fn row_at(census: &Census, at: usize) -> Option<(u32, u32, u64, u32, u64)> {
        census.rows().get(at).map(fields)
    }

    /// The fields of the row that lists `entry` for `shard`, as the census encodes them.
    fn listing(shard: Shard, entry: Entry) -> Option<(u32, u32, u64, u32, u64)> {
        let target = entry.target;
        Some((
            shard.get(),
            target.generation.get() as u32,
            target.owner.get(),
            target.attempts,
            entry.host.get(),
        ))
    }

    /// The inputs one admission proof shares across its shards.
    struct Admission {
        zone: Zone,
        entries: [Entry; ENTRIES],
        record: ShardRecord,
        candidate: HostReport,
        attach: Attach,
        lost: Evidence,
        population: Population,
    }

    /// The outcomes the admissions into one census reached, for the covers of its harness.
    #[derive(Default)]
    struct Admitted {
        inserted: bool,
        updated: bool,
        displaced: bool,
        unwritable: bool,
        unchanged: bool,
        ineligible: bool,
        closed: bool,
        pending_headroom: bool,
        taken: bool,
        standby_taken: bool,
        full: bool,
    }

    impl Admission {
        fn any() -> Self {
            Self {
                zone: Zone(kani::any()),
                entries: entries(),
                record: shard_record(),
                candidate: candidate(),
                attach: attach(),
                lost: Evidence::any(),
                population: Population { cap: kani::any() },
            }
        }

        /// The admission of the record's slot under shard `shard` into `census`, the census of the first `N`
        /// entries, checked against the reference outcome and, when it returns a census, against the rows that
        /// census must hold. Records the outcome in `seen`.
        fn check<const N: usize>(&self, census: &Census, shard: u32, seen: &mut Admitted) {
            let record = ShardRecord {
                shard: Shard::new(shard).unwrap(),
                ..self.record
            };
            let lost = self.lost;
            let admitted =
                self.population
                    .admit(census, &record, &self.candidate, self.attach, |h| {
                        lost.holds(h)
                    });

            let host = self.candidate.writer.host;
            let entry = Entry {
                target: tenure(&record),
                host,
            };
            let (place, held) = slot::<N>(&fixed_shards(), &self.entries, record.shard);
            let pending = (0..N)
                .filter(|&at| self.entries[at].host == host && shard_at(at) != record.shard)
                .count() as u64;
            let room = |gauge: Gauge, owed: u64| match gauge {
                Gauge::Known { used, limit } => used.saturating_add(owed) < limit.get(),
                Gauge::Unavailable => false,
            };
            let headroom = self.candidate.host.headroom;
            let incumbent = match held {
                Some(held) if held.host != record.owner => Some(held.host),
                _ => record.standby,
            };
            let cap = self.population.cap.min(MAX_SLOTS);
            let reference = if record.attempts == 0 || host == record.owner {
                Err(Refusal::Ineligible)
            } else if held == Some(entry) {
                Ok(false)
            } else if self.attach == Attach::Closed {
                Err(Refusal::Closed)
            } else if (self.attach == Attach::Open && !room(headroom.attachments, pending))
                || !room(headroom.recovery, 0)
            {
                Err(Refusal::Headroom)
            } else if incumbent.is_some_and(|h| h != host && !lost.holds(h)) {
                Err(Refusal::Taken)
            } else if held.is_none() && N >= cap {
                Err(Refusal::Full)
            } else {
                Ok(true)
            };
            let outcome = admitted
                .as_ref()
                .map(Option::is_some)
                .map_err(|&refusal| refusal);
            assert_eq!(outcome, reference);

            let inserted = held.is_none();
            if let Ok(Some(next)) = &admitted {
                assert_eq!(next.zone(), census.zone());
                assert_eq!(row_at(next, place), listing(record.shard, entry));
                // "the per-AZ census never lists more than cap shards when one is added"
                framed(next, N + usize::from(inserted));
                assert_eq!(next.len(), N + usize::from(inserted));
                if inserted {
                    assert!(next.len() <= cap);
                }
                // This `if` inside `for at in 0..N` visits the indices `(0..N).filter(|&at| at != place || inserted)`
                // yields, in the same order; the test sits in the body because, at a listed shard with a following
                // row, CBMC unwinds that adapter's state to the loop bound of 30, and folds this loop's bounds to N
                // iterations.
                for at in 0..N {
                    if at != place || inserted {
                        let moved = if inserted && at >= place { at + 1 } else { at };
                        assert_eq!(row_at(next, moved), listing(shard_at(at), self.entries[at]));
                    }
                }
                // The store client writes the census exactly when every entry encodes.
                assert_eq!(next.sound, record.attempts <= ATTEMPTS_MAX);
                seen.unwritable |= !next.sound;
            }
            let decided_by_pending = self.attach == Attach::Open
                && room(headroom.attachments, 0)
                && !room(headroom.attachments, pending)
                && room(headroom.recovery, 0);
            seen.inserted |= outcome == Ok(true) && inserted;
            seen.updated |= outcome == Ok(true) && !inserted;
            seen.displaced |=
                outcome == Ok(true) && !inserted && incumbent.is_some_and(|h| h != host);
            seen.unchanged |= outcome == Ok(false);
            seen.ineligible |= outcome == Err(Refusal::Ineligible);
            seen.closed |= outcome == Err(Refusal::Closed);
            seen.pending_headroom |= outcome == Err(Refusal::Headroom) && decided_by_pending;
            seen.taken |= outcome == Err(Refusal::Taken);
            seen.standby_taken |= outcome == Err(Refusal::Taken)
                && held.is_some_and(|held| held.host == record.owner);
            seen.full |= outcome == Err(Refusal::Full);
        }

        /// The admissions into the census of the first `N` entries of a shard before, at and after each listed one.
        fn every_place<const N: usize>(&self) -> Admitted {
            let census = census::<N>(self.zone, &fixed_shards(), &self.entries);
            let mut seen = Admitted::default();
            for shard in places::<N>() {
                self.check::<N>(&census, shard, &mut seen);
            }
            seen
        }

        /// The admission into the census of the first `N` entries of the shard at index `at` of [`places`].
        fn at_place<const N: usize>(&self, at: usize) -> Admitted {
            let census = census::<N>(self.zone, &fixed_shards(), &self.entries);
            let mut seen = Admitted::default();
            let shard = places::<N>().nth(at).unwrap();
            self.check::<N>(&census, shard, &mut seen);
            seen
        }

        /// The admission into an empty census of the record under its own shard, any shard.
        fn of_any_shard(&self) -> Admitted {
            let census = census::<0>(self.zone, &fixed_shards(), &self.entries);
            let mut seen = Admitted::default();
            self.check::<0>(&census, self.record.shard.get(), &mut seen);
            seen
        }
    }

    /// Over one call with any record and any loss evidence: `need` answers nothing at `E = 0` or with a standby the
    /// evidence does not show lost, and otherwise `Fresh` when the evidence shows the owner lost and `Standby` when it
    /// does not. Bounds: one call of the loop-free `need` at the default unwinding.
    #[kani::proof]
    fn a_shard_needs_a_designation_only_without_a_live_standby() {
        let record = shard_record();
        let lost = Evidence::any();
        let needed = need(&record, |h| lost.holds(h));
        let live_standby = record.standby.is_some_and(|standby| !lost.holds(standby));
        let reference = if record.attempts == 0 || live_standby {
            None
        } else if lost.holds(record.owner) {
            Some(Need::Fresh)
        } else {
            Some(Need::Standby)
        };
        assert_eq!(needed, reference);
        kani::cover!(needed == Some(Need::Fresh) && record.standby.is_some());
        kani::cover!(needed == Some(Need::Standby) && record.standby.is_none());
        kani::cover!(needed == Some(Need::Standby) && record.standby.is_some());
        kani::cover!(needed.is_none() && record.attempts > 0);
    }

    /// Over admissions into an empty census of a record under any shard: the result is the reference refusal or
    /// admission, and an admitted census lists the record's shard and tenure and the candidate alone, only when `cap`
    /// is above zero. Covers witness an insertion, an unwritable admission, and the `Ineligible`, `Closed` and `Full`
    /// refusals. Bounds: those in the module documentation.
    #[kani::proof]
    #[kani::unwind(30)]
    fn an_admission_into_an_empty_census_keeps_the_cap() {
        let seen = Admission::any().of_any_shard();
        kani::cover!(seen.inserted);
        kani::cover!(seen.unwritable);
        kani::cover!(seen.ineligible);
        kani::cover!(seen.closed);
        kani::cover!(seen.full);
    }

    /// Over admissions into a census of one entry at every place of the record's shard: the result is the reference
    /// refusal or admission, and an admitted census keeps the zone, writes the record's tenure and the candidate into
    /// the shard's slot at its place, keeps the other entry, adds one entry only below `min(cap, MAX_SLOTS)` and keeps
    /// the count when the shard was listed. Covers witness an insertion, an unwritable admission, an update, an update
    /// displacing a lost incumbent, an unchanged slot, each refusal, a `Headroom` refusal the pending count decides and
    /// a `Taken` refusal through the record's standby. Bounds: those in the module documentation.
    #[kani::proof]
    #[kani::unwind(30)]
    fn an_admission_into_one_entry_keeps_the_cap_and_the_other_entry() {
        let seen = Admission::any().every_place::<1>();
        kani::cover!(seen.inserted);
        kani::cover!(seen.unwritable);
        kani::cover!(seen.ineligible);
        kani::cover!(seen.closed);
        kani::cover!(seen.updated);
        kani::cover!(seen.displaced);
        kani::cover!(seen.unchanged);
        kani::cover!(seen.pending_headroom);
        kani::cover!(seen.taken);
        kani::cover!(seen.standby_taken);
        kani::cover!(seen.full);
    }

    /// Over admissions into a census of two entries of a record whose shard lies below the first listed shard: the
    /// result is the reference refusal or admission, and an admitted census adds the record's row at that place only
    /// below `min(cap, MAX_SLOTS)` and keeps every other entry in order. Covers witness an insertion, an unwritable
    /// admission, the `Ineligible`, `Closed`, `Taken` and `Full` refusals, and a `Headroom` refusal the pending count
    /// decides. Bounds: those in the module documentation.
    #[kani::proof]
    #[kani::unwind(30)]
    fn an_admission_into_two_entries_of_a_shard_below_the_first() {
        let seen = Admission::any().at_place::<2>(0);
        kani::cover!(seen.inserted);
        kani::cover!(seen.unwritable);
        kani::cover!(seen.ineligible);
        kani::cover!(seen.closed);
        kani::cover!(seen.pending_headroom);
        kani::cover!(seen.taken);
        kani::cover!(seen.full);
    }

    /// Over admissions into a census of two entries of a record whose shard is the first listed shard: the result is
    /// the reference refusal or admission, and an admitted census writes the record's tenure and the candidate over
    /// that shard's row, keeps the count and keeps every other entry in order; no admission here adds a row, so the cap
    /// assertion is unreached. Covers witness an update, an update displacing a lost incumbent, an unwritable
    /// admission, an unchanged slot, the `Ineligible`, `Closed` and `Taken` refusals, a `Taken` refusal through the
    /// record's standby, and a `Headroom` refusal the pending count decides. Bounds: those in the module documentation.
    #[kani::proof]
    #[kani::unwind(30)]
    fn an_admission_into_two_entries_of_the_first_shard() {
        let seen = Admission::any().at_place::<2>(1);
        kani::cover!(seen.unwritable);
        kani::cover!(seen.ineligible);
        kani::cover!(seen.closed);
        kani::cover!(seen.updated);
        kani::cover!(seen.displaced);
        kani::cover!(seen.unchanged);
        kani::cover!(seen.pending_headroom);
        kani::cover!(seen.taken);
        kani::cover!(seen.standby_taken);
    }

    /// Over admissions into a census of two entries of a record whose shard lies just above the first listed shard,
    /// with the properties and covers of [`an_admission_into_two_entries_of_a_shard_below_the_first`]. Bounds: those in
    /// the module documentation.
    #[kani::proof]
    #[kani::unwind(30)]
    fn an_admission_into_two_entries_of_a_shard_above_the_first() {
        let seen = Admission::any().at_place::<2>(2);
        kani::cover!(seen.inserted);
        kani::cover!(seen.unwritable);
        kani::cover!(seen.ineligible);
        kani::cover!(seen.closed);
        kani::cover!(seen.pending_headroom);
        kani::cover!(seen.taken);
        kani::cover!(seen.full);
    }

    /// Over admissions into a census of two entries of a record whose shard is the second listed shard, with the
    /// properties and covers of [`an_admission_into_two_entries_of_the_first_shard`]. Bounds: those in the module
    /// documentation.
    #[kani::proof]
    #[kani::unwind(30)]
    fn an_admission_into_two_entries_of_the_second_shard() {
        let seen = Admission::any().at_place::<2>(3);
        kani::cover!(seen.unwritable);
        kani::cover!(seen.ineligible);
        kani::cover!(seen.closed);
        kani::cover!(seen.updated);
        kani::cover!(seen.displaced);
        kani::cover!(seen.unchanged);
        kani::cover!(seen.pending_headroom);
        kani::cover!(seen.taken);
        kani::cover!(seen.standby_taken);
    }

    /// Over admissions into a census of two entries of a record whose shard lies just above the second listed shard,
    /// with the properties and covers of [`an_admission_into_two_entries_of_a_shard_below_the_first`]. Bounds: those in
    /// the module documentation.
    #[kani::proof]
    #[kani::unwind(30)]
    fn an_admission_into_two_entries_of_a_shard_above_the_second() {
        let seen = Admission::any().at_place::<2>(4);
        kani::cover!(seen.inserted);
        kani::cover!(seen.unwritable);
        kani::cover!(seen.ineligible);
        kani::cover!(seen.closed);
        kani::cover!(seen.pending_headroom);
        kani::cover!(seen.taken);
        kani::cover!(seen.full);
    }

    /// Over admissions into a census of three entries of a record whose shard lies below the first listed shard, with
    /// the properties and covers of [`an_admission_into_two_entries_of_a_shard_below_the_first`]. Bounds: those in the
    /// module documentation.
    #[kani::proof]
    #[kani::unwind(30)]
    fn an_admission_into_three_entries_of_a_shard_below_the_first() {
        let seen = Admission::any().at_place::<3>(0);
        kani::cover!(seen.inserted);
        kani::cover!(seen.unwritable);
        kani::cover!(seen.ineligible);
        kani::cover!(seen.closed);
        kani::cover!(seen.pending_headroom);
        kani::cover!(seen.taken);
        kani::cover!(seen.full);
    }

    /// Over admissions into a census of three entries of a record whose shard is the first listed shard, with the
    /// properties and covers of [`an_admission_into_two_entries_of_the_first_shard`]. Bounds: those in the module
    /// documentation.
    #[kani::proof]
    #[kani::unwind(30)]
    fn an_admission_into_three_entries_of_the_first_shard() {
        let seen = Admission::any().at_place::<3>(1);
        kani::cover!(seen.unwritable);
        kani::cover!(seen.ineligible);
        kani::cover!(seen.closed);
        kani::cover!(seen.updated);
        kani::cover!(seen.displaced);
        kani::cover!(seen.unchanged);
        kani::cover!(seen.pending_headroom);
        kani::cover!(seen.taken);
        kani::cover!(seen.standby_taken);
    }

    /// Over admissions into a census of three entries of a record whose shard lies just above the first listed shard,
    /// with the properties and covers of [`an_admission_into_two_entries_of_a_shard_below_the_first`]. Bounds: those in
    /// the module documentation.
    #[kani::proof]
    #[kani::unwind(30)]
    fn an_admission_into_three_entries_of_a_shard_above_the_first() {
        let seen = Admission::any().at_place::<3>(2);
        kani::cover!(seen.inserted);
        kani::cover!(seen.unwritable);
        kani::cover!(seen.ineligible);
        kani::cover!(seen.closed);
        kani::cover!(seen.pending_headroom);
        kani::cover!(seen.taken);
        kani::cover!(seen.full);
    }

    /// Over admissions into a census of three entries of a record whose shard is the second listed shard, with the
    /// properties and covers of [`an_admission_into_two_entries_of_the_first_shard`]. Bounds: those in the module
    /// documentation.
    #[kani::proof]
    #[kani::unwind(30)]
    fn an_admission_into_three_entries_of_the_second_shard() {
        let seen = Admission::any().at_place::<3>(3);
        kani::cover!(seen.unwritable);
        kani::cover!(seen.ineligible);
        kani::cover!(seen.closed);
        kani::cover!(seen.updated);
        kani::cover!(seen.displaced);
        kani::cover!(seen.unchanged);
        kani::cover!(seen.pending_headroom);
        kani::cover!(seen.taken);
        kani::cover!(seen.standby_taken);
    }

    /// Over admissions into a census of three entries of a record whose shard lies just above the second listed shard,
    /// with the properties and covers of [`an_admission_into_two_entries_of_a_shard_below_the_first`]. Bounds: those in
    /// the module documentation.
    #[kani::proof]
    #[kani::unwind(30)]
    fn an_admission_into_three_entries_of_a_shard_above_the_second() {
        let seen = Admission::any().at_place::<3>(4);
        kani::cover!(seen.inserted);
        kani::cover!(seen.unwritable);
        kani::cover!(seen.ineligible);
        kani::cover!(seen.closed);
        kani::cover!(seen.pending_headroom);
        kani::cover!(seen.taken);
        kani::cover!(seen.full);
    }

    /// Over admissions into a census of three entries of a record whose shard is the third listed shard, with the
    /// properties and covers of [`an_admission_into_two_entries_of_the_first_shard`]. Bounds: those in the module
    /// documentation.
    #[kani::proof]
    #[kani::unwind(30)]
    fn an_admission_into_three_entries_of_the_third_shard() {
        let seen = Admission::any().at_place::<3>(5);
        kani::cover!(seen.unwritable);
        kani::cover!(seen.ineligible);
        kani::cover!(seen.closed);
        kani::cover!(seen.updated);
        kani::cover!(seen.displaced);
        kani::cover!(seen.unchanged);
        kani::cover!(seen.pending_headroom);
        kani::cover!(seen.taken);
        kani::cover!(seen.standby_taken);
    }

    /// Over admissions into a census of three entries of a record whose shard lies just above the third listed shard,
    /// with the properties and covers of [`an_admission_into_two_entries_of_a_shard_below_the_first`]. Bounds: those in
    /// the module documentation.
    #[kani::proof]
    #[kani::unwind(30)]
    fn an_admission_into_three_entries_of_a_shard_above_the_third() {
        let seen = Admission::any().at_place::<3>(6);
        kani::cover!(seen.inserted);
        kani::cover!(seen.unwritable);
        kani::cover!(seen.ineligible);
        kani::cover!(seen.closed);
        kani::cover!(seen.pending_headroom);
        kani::cover!(seen.taken);
        kani::cover!(seen.full);
    }

    /// Any recorded role, or none.
    fn role() -> Option<RecordedRole> {
        let role = match kani::any::<u8>() % 5 {
            0 => Some(RecordedRole::Owner),
            1 => Some(RecordedRole::Standby),
            2 => Some(RecordedRole::Replacement),
            3 => Some(RecordedRole::Unrecorded),
            _ => None,
        };
        // A new variant fails to compile here; the selector above then needs an arm for it.
        match role {
            Some(
                RecordedRole::Owner
                | RecordedRole::Standby
                | RecordedRole::Replacement
                | RecordedRole::Unrecorded,
            )
            | None => role,
        }
    }

    /// A volume entry of a host report that lists `shard` in `role`, any of three volumes, every other field
    /// unavailable or absent.
    fn reported(shard: Shard, role: Option<RecordedRole>) -> VolumeEntry {
        VolumeEntry {
            volume: volume(),
            shard,
            role,
            tenure: None,
            volume_state: None,
            serving: None,
            withheld: false,
            quarantine: false,
            flip: false,
            withdrawal: None,
            refusal: None,
            enumeration: Enumeration::Unavailable,
            watermark: Watermark::Unavailable,
            report_age_us: None,
            own_records: None,
            checkpoint: None,
            checkpoint_age_us: None,
            captures: Captures {
                refused: None,
                abandoned: None,
            },
            exit: None,
            pressure: Pressure {
                frontier: Gauge::Unavailable,
                ancestry: Gauge::Unavailable,
                quarantine: Gauge::Unavailable,
                full: Gauge::Unavailable,
            },
            registrants: None,
            hold: None,
            readiness: None,
            metadata: None,
            load_refusal: None,
            recovery: Recovery::UNAVAILABLE,
            phase: None,
            ended: None,
            named: None,
            roll_due: None,
            roll_active: None,
            publication_due: None,
            times: RecoveryTimes::UNAVAILABLE,
            retention: None,
            suffix: Backlog::UNAVAILABLE,
            recovery_io: RecoveryIo::UNAVAILABLE,
            attaches: Gauge::Unavailable,
            store: StoreOutcomes::UNAVAILABLE,
            coverage: Coverage::UNAVAILABLE,
            invalidations: Gauge::Unavailable,
            read_defects: None,
            served: None,
        }
    }

    /// The inputs the pending-count proof and its control share: a census of three entries, a candidate whose report
    /// lists two volume entries, each under any shard in any recorded role or none, and a record under any shard.
    struct Pending {
        entries: [Entry; ENTRIES],
        census: Census,
        candidate: HostReport,
        /// The record's shard.
        shard: Shard,
    }

    impl Pending {
        fn any() -> Self {
            let entries = entries();
            let census = census::<ENTRIES>(Zone(kani::any()), &fixed_shards(), &entries);
            let mut candidate = candidate();
            candidate.entries = vec![reported(shard(), role()), reported(shard(), role())];
            let shard = shard();
            Self {
                entries,
                census,
                candidate,
                shard,
            }
        }

        /// Whether the report lists `held` in the standby role, for `standby`, or in another role or none.
        fn listed(&self, held: Shard, standby: bool) -> bool {
            self.candidate.entries.iter().any(|seen| {
                seen.shard == held && (seen.role == Some(RecordedRole::Standby)) == standby
            })
        }

        /// Whether the entry at `at` is on the candidate's host under a shard other than the record's.
        fn named(&self, at: usize) -> bool {
            self.entries[at].host == self.candidate.writer.host && shard_at(at) != self.shard
        }

        /// Whether the standby role exempts the entry at `at` from the count.
        fn exempt(&self, at: usize) -> bool {
            self.named(at) && self.listed(shard_at(at), true)
        }

        /// The reference count: the entries on the candidate's host under a shard other than the record's that the
        /// report lists in no standby role. The proof asserts `Census::pending` equal to it, and the control's covers
        /// compare the planted count with it.
        fn reference(&self) -> u64 {
            (0..ENTRIES)
                .filter(|&at| self.named(at) && !self.exempt(at))
                .count() as u64
        }
    }

    /// Over the pending count of a census of three entries, for a candidate whose report lists two volume entries,
    /// each under any shard in any recorded role or none, and a record under any shard: the count is the number of
    /// entries whose host is the candidate's, whose shard differs from the record's, and whose shard the report lists
    /// in no standby role. Covers witness an entry the standby role exempts, an entry counted beside a report entry
    /// of its shard in another role, and a count of three. Bounds: the census and its entries are those of the other
    /// census proofs; the report lists two entries.
    #[kani::proof]
    #[kani::unwind(30)]
    fn the_pending_count_exempts_each_shard_the_report_lists_in_the_standby_role() {
        let case = Pending::any();
        let expected = case.reference();
        assert_eq!(case.census.pending(case.shard, &case.candidate), expected);
        kani::cover!((0..ENTRIES).any(|at| case.exempt(at)));
        kani::cover!(
            (0..ENTRIES).any(|at| {
                case.named(at) && !case.exempt(at) && case.listed(shard_at(at), false)
            })
        );
        kani::cover!(expected == 3);
    }

    /// The pending-count control inverts the standby predicate for each reported entry.
    ///
    /// The inverted report makes the production count exempt an entry whose shard the original report lists outside
    /// the standby role. The control reads the inputs and the reference count of the proof through [`Pending`].
    /// Covers witness the plant counting an entry the standby role exempts, and exempting an entry the reference
    /// counts.
    #[kani::proof]
    #[kani::unwind(30)]
    fn the_pending_count_of_an_inverted_standby_role_differs_from_the_reference() {
        let case = Pending::any();
        let reference = case.reference();
        let mut negated = case.candidate.clone();
        for seen in &mut negated.entries {
            seen.role = match seen.role {
                Some(RecordedRole::Standby) => None,
                _ => Some(RecordedRole::Standby),
            };
        }
        let planted = case.census.pending(case.shard, &negated);
        kani::cover!(planted > reference);
        kani::cover!(planted < reference);
    }

    /// The inputs one release proof shares across its shards.
    struct Release {
        zone: Zone,
        /// The shards the census lists, ascending.
        shards: [Shard; ENTRIES],
        entries: [Entry; ENTRIES],
        record: ShardRecord,
        live: Evidence,
    }

    /// The outcomes the releases from one census reached, for the covers of its harness.
    #[derive(Default)]
    struct Released {
        dropped: bool,
        dropped_owner_live: bool,
        kept_standby: bool,
        kept_tenure: bool,
        kept_live: bool,
        unlisted_below: bool,
        unlisted_above: bool,
    }

    impl Release {
        /// A release from a census that lists the shards [`shard_at`] names.
        fn any() -> Self {
            Self {
                zone: Zone(kani::any()),
                shards: fixed_shards(),
                entries: entries(),
                record: shard_record(),
                live: Evidence::any(),
            }
        }

        /// A release from a census whose first `N` shards are any ascending shards.
        fn of_any_shards<const N: usize>() -> Self {
            let shards: [Shard; ENTRIES] = core::array::from_fn(|_| shard());
            kani::assume(shards[..N].is_sorted_by(|low, high| low < high));
            Self {
                shards,
                ..Self::any()
            }
        }

        /// The release of the record's slot under shard `shard` from `census`, the census of the first `N` entries,
        /// checked against the reference condition and, when it drops the entry, against the rows the result must
        /// hold. Records the outcome in `seen`.
        fn check<const N: usize>(&self, census: &Census, shard: u32, seen: &mut Released) {
            let record = ShardRecord {
                shard: Shard::new(shard).unwrap(),
                ..self.record
            };
            let live = self.live;
            let released = census.released(&record, |h| live.holds(h));
            let (place, held) = slot::<N>(&self.shards, &self.entries, record.shard);
            let drops = held.is_some_and(|entry| {
                record.standby.is_none()
                    && entry.target != tenure(&record)
                    && (entry.host == record.owner || !live.holds(entry.host))
            });
            assert_eq!(released.is_some(), drops);
            if let Some(next) = &released {
                assert_eq!(next.zone(), census.zone());
                framed(next, N - 1);
                assert_eq!(next.len() + 1, N);
                for at in (0..N).filter(|&at| at != place) {
                    let moved = if at > place { at - 1 } else { at };
                    assert_eq!(
                        row_at(next, moved),
                        listing(self.shards[at], self.entries[at])
                    );
                }
            }
            seen.unlisted_below |= held.is_none() && place == 0;
            seen.unlisted_above |= held.is_none() && place == N;
            if let Some(entry) = held {
                let same_tenure = entry.target == tenure(&record);
                let live_other = entry.host != record.owner && live.holds(entry.host);
                seen.dropped |= drops;
                seen.dropped_owner_live |=
                    drops && entry.host == record.owner && live.holds(entry.host);
                seen.kept_standby |=
                    !drops && record.standby.is_some() && !same_tenure && !live_other;
                seen.kept_tenure |=
                    !drops && record.standby.is_none() && same_tenure && !live_other;
                seen.kept_live |= !drops && record.standby.is_none() && !same_tenure && live_other;
            }
        }

        /// The releases from the census of the first `N` entries of a shard before, at and after each listed one.
        fn every_place<const N: usize>(&self) -> Released {
            let census = census::<N>(self.zone, &self.shards, &self.entries);
            let mut seen = Released::default();
            for shard in places::<N>() {
                self.check::<N>(&census, shard, &mut seen);
            }
            seen
        }

        /// The release from the census of the first entry of the record under its own shard, any shard.
        fn of_any_shard(&self) -> Released {
            let census = census::<1>(self.zone, &self.shards, &self.entries);
            let mut seen = Released::default();
            self.check::<1>(&census, self.record.shard.get(), &mut seen);
            seen
        }
    }

    /// Over releases from a census of one entry under any shard, of a record under any shard: the census drops the
    /// entry exactly when it lists one for the record's shard, the record names no standby and holds another
    /// `(g, owner, E)`, and the entry's host is the record's owner or shows no live attach; the result keeps the zone.
    /// Covers witness a drop, a drop of the owner's entry while the owner shows a live attach, each reason an entry
    /// stays, and a record whose shard lies below and above the listed one. Bounds: those in the module documentation.
    #[kani::proof]
    #[kani::unwind(30)]
    fn a_release_from_one_entry_drops_only_a_settled_entry() {
        let seen = Release::of_any_shards::<1>().of_any_shard();
        kani::cover!(seen.dropped);
        kani::cover!(seen.dropped_owner_live);
        kani::cover!(seen.kept_standby);
        kani::cover!(seen.kept_tenure);
        kani::cover!(seen.kept_live);
        kani::cover!(seen.unlisted_below);
        kani::cover!(seen.unlisted_above);
    }

    /// Over releases from a census of two entries at every place of the record's shard, with the properties of
    /// [`a_release_from_one_entry_drops_only_a_settled_entry`] and every other entry kept in order. Bounds: those in
    /// the module documentation.
    #[kani::proof]
    #[kani::unwind(30)]
    fn a_release_from_two_entries_drops_only_a_settled_entry_and_keeps_every_other() {
        let seen = Release::any().every_place::<2>();
        kani::cover!(seen.dropped);
        kani::cover!(seen.dropped_owner_live);
        kani::cover!(seen.kept_standby);
        kani::cover!(seen.kept_tenure);
        kani::cover!(seen.kept_live);
        kani::cover!(seen.unlisted_below);
        kani::cover!(seen.unlisted_above);
    }

    /// Over releases from a census of three entries at every place of the record's shard, with the properties of
    /// [`a_release_from_one_entry_drops_only_a_settled_entry`] and every other entry kept in order. Bounds: those in
    /// the module documentation.
    #[kani::proof]
    #[kani::unwind(30)]
    fn a_release_from_three_entries_drops_only_a_settled_entry_and_keeps_every_other() {
        let seen = Release::any().every_place::<3>();
        kani::cover!(seen.dropped);
        kani::cover!(seen.dropped_owner_live);
        kani::cover!(seen.kept_standby);
        kani::cover!(seen.kept_tenure);
        kani::cover!(seen.kept_live);
        kani::cover!(seen.unlisted_below);
        kani::cover!(seen.unlisted_above);
    }
}
