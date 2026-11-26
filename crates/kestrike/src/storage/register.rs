//! Reader registration: one of `R` preallocated records per registered
//! reader, and the protected interval that pins the era before observation.
//!
//! A [`Registration`] reserves one reader record. It borrows the storage
//! and is not `Clone`; it is `Send` and `Sync` whenever the storage is
//! `Sync`, and it holds no pin between protected intervals. A protected
//! interval is a [`Protected`] guard taken through `&mut Registration` by
//! the synchronous lookup path alone: entry, exit and the candidate snapshot
//! are private to this crate, so no caller can hold a guard or a copied
//! candidate, and the lookup returns its lease only after ending the pin.
//! The guard holds the registration's exclusive borrow, so at most one
//! interval exists per registration, and it is neither `Send` nor `Sync`: a
//! pin never crosses a thread handoff. Its wall-clock duration is bounded by
//! the caller's work, not promised.
//!
//! Admission is ordered against close through the one `SeqCst` cutoff, read
//! twice on the way into protection. A record is claimed by one `AcqRel`
//! `swap`, then the cutoff is read, and a close that landed first
//! gives the record back and refuses; that read yields the refund, not an
//! ordered witness, since the claim is not `SeqCst`. Entry pins the era with
//! `grace::pin`: a `Relaxed` load that refuses unless the record's pin is
//! the inactive zero, then a `SeqCst` store of the era; entry then reads the
//! cutoff with `SeqCst`, and a close that landed first clears the new pin
//! and refuses. Because both the pin store and that load are `SeqCst`, a
//! read that returns open places the pin store before the close in the
//! `SeqCst` total order, so a `SeqCst` pin load ordered after the close
//! sees the pin while the interval is active, or its clearing store after
//! the interval's protected work has ended ([`Storage::close`]). The pin
//! store follows the inactive check, so an active pin stays in place. Every
//! exit finishes the interval's protected reads and refunds before the
//! clearing store.
//!
//! The record also parks the reader's idle lease credits, in its own word
//! and on a return line of its own: the `lease` module describes how a
//! lookup borrows them from the engine-wide count and how its leases return
//! to them. Dropping the handle gives the idle credits back, clears the
//! record and returns it. A leaked handle
//! keeps its record claimed and finalization blocked for good; a leaked guard
//! keeps its pin, and the record refuses every later interval rather than
//! raise the pin over protection the leaked interval may still rely on.
//! Only dropping the registration clears that pin, and the registration
//! cannot be dropped while any guard borrows it. Nothing unregisters a
//! reader by force. Because every live handle borrows the storage, dropping
//! or finalizing the storage while one exists is a compile error; only a
//! handle leaked with `mem::forget` ends its borrow early, and it is then
//! finalization's inspection of the claimed records that blocks.
//!
//! The interval counter in each record is a statistic: it saturates at
//! `u64::MAX` instead of wrapping and authorizes nothing.
//!
//! Compile-time misuse: protected entry is private, a registration cannot be
//! cloned or forged, and the storage cannot be dropped under a registration.
//!
//! ```compile_fail,E0624
//! # use kestrike::storage::*;
//! # fn f(mut registration: Registration<'_, LinuxPlatform>) {
//! let protected = registration.enter();
//! # }
//! ```
//!
//! ```compile_fail,E0599
//! # use kestrike::storage::*;
//! # fn f(registration: Registration<'_, LinuxPlatform>) {
//! let copy = registration.clone();
//! # }
//! ```
//!
//! ```compile_fail,E0451
//! # use kestrike::storage::*;
//! # fn f(storage: &Storage<LinuxPlatform>) {
//! let forged = Registration { storage, index: 0, record: unreachable!() };
//! # }
//! ```
//!
//! ```compile_fail,E0505
//! # use kestrike::storage::*;
//! # fn f(mut storage: Storage<LinuxPlatform>) {
//! let registration = storage.register().unwrap();
//! drop(storage);
//! let _ = registration.index();
//! # }
//! ```
//!
//! Positive use: the handle moved across threads between lookups, each
//! lookup pinning and ending its own interval.
//!
//! ```no_run
//! # use kestrike::storage::*;
//! # fn f(storage: &Storage<LinuxPlatform>) -> Result<(), LookupError> {
//! let mut registration = storage.register().ok().unwrap();
//! let mut budget = WorkBudget::new(64);
//! let first = registration.lookup(&[0x5A; 32], 3, &mut budget);
//! let mut moved = std::thread::scope(|scope| scope.spawn(move || registration).join().unwrap());
//! let second = moved.lookup(&[0x5A; 32], 3, &mut budget);
//! # let _ = (first, second);
//! # Ok(())
//! # }
//! ```
//!
//! Stable rustdoc does not check the error codes above; they record the
//! intended cause (E0624 private entry, E0599 clone, E0451 forged handle,
//! E0505 storage dropped under a registration) for a reader, and
//! `cargo +nightly test --doc` verifies them. The private tests below
//! inspect the guard's exclusive borrow, its `!Send`/`!Sync` marker and its
//! exit and leak behavior directly.

use std::marker::PhantomData;
use std::sync::atomic::Ordering;

use super::grace::{self, ERA_TERMINAL, INACTIVE, PinRefused, Sequential};
use super::image::RegistrationRecord;
use super::lease::drain_record;
use super::os::Platform;
use super::owner::Storage;
use super::probe::{self, Primitive};

/// Position of a registration record. An index alone confers no access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RegistrationIndex(pub usize);

/// Why no registration was issued. Nothing changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterError {
    /// Every one of the `R` records is claimed.
    ReaderLimit,
    /// Admission is closed, or the storage is drained.
    Closed,
}

/// Why no protected interval was entered. On return the record holds no new
/// pin; `Leaked` leaves the earlier pin intact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinError {
    /// The era counter is terminal; no reader can pin again, for good.
    /// Existing pins and leases are unaffected.
    Contended,
    /// An earlier interval on this registration was leaked without ending,
    /// so its pin is still in place; only dropping the registration clears
    /// it.
    Leaked,
    /// Admission closed before the pin could be witnessed open; the pin the
    /// entry stored was cleared again.
    Closed,
}

/// One registered reader's claim on a registration record. See the module
/// documentation.
#[must_use = "dropping the registration returns its record"]
pub struct Registration<'s, P: Platform> {
    storage: &'s Storage<P>,
    index: usize,
    /// The claimed record, resolved once at registration so an interval's
    /// pin and unpin address it directly.
    record: &'s RegistrationRecord,
}

impl<P: Platform> std::fmt::Debug for Registration<'_, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registration")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

/// One protected interval: the era pinned on entry stays pinned until this
/// guard exits, so nothing retired at or after that era can be reclaimed
/// while the holder observes it. Private to the crate, and neither `Send`
/// nor `Sync`.
#[must_use = "dropping the guard ends the protected interval; nothing observed afterwards is protected"]
pub(crate) struct Protected<'r, 's, P: Platform> {
    registration: &'r mut Registration<'s, P>,
    /// A pin belongs to the thread that stored it and never crosses a
    /// handoff; the marker removes `Send` and `Sync`.
    thread_bound: PhantomData<*const ()>,
}

/// What one registration record reports about itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistrationReport {
    /// Whether a handle owns the record.
    pub claimed: bool,
    /// The era pinned by an interval in progress, or `None` when unpinned.
    pub pinned_era: Option<u64>,
    /// Protected intervals entered through the record so far; saturates at
    /// `u64::MAX`.
    pub intervals: u64,
}

/// The era counter and grace certificate, read without any gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EraReport {
    /// Current era; the value the next pin would hold.
    pub era: u64,
    /// Highest era below which every retirement has completed its grace.
    pub certified: u64,
    /// Whether the era is terminal, so pins are refused.
    pub terminal: bool,
}

impl<P: Platform> Storage<P> {
    /// Claims one registration record and returns its handle.
    ///
    /// Fixed work: at most one load per record over the `R` records, one
    /// swap per record found unclaimed, one load of the claimed bound and
    /// one read-modify-write when it is raised, no allocation and no gate. A
    /// claimed
    /// record costs its reader nothing: the scan reads it and leaves its
    /// line in place; only a record seen unclaimed is written.
    ///
    /// # Errors
    ///
    /// `ReaderLimit` if every record is claimed; `Closed` if admission is
    /// closed or the storage is drained. Nothing is claimed on error.
    pub fn register(&self) -> Result<Registration<'_, P>, RegisterError> {
        if !self.is_live() || self.is_closed() {
            return Err(RegisterError::Closed);
        }
        let records = self.registrations();
        // The swap returns the value it replaced: `false` claims the record,
        // `true` means another claimant won the race since the load and the
        // record stays theirs.
        let index = records
            .iter()
            .position(|record| {
                !record.claimed.load(Ordering::Relaxed)
                    && !record.claimed.swap(true, Ordering::AcqRel)
            })
            .ok_or(RegisterError::ReaderLimit)?;
        // The claimed bound covers this record before any pin it can take,
        // in the `SeqCst` order: a pass whose bound load did not cover it
        // precedes this load, or the read-modify-write that raises the
        // bound when the load finds it short, and so precedes the era load
        // of every pin the record takes (the `grace` module states the
        // argument). Only a registration that raises the bound writes its
        // line, which the era shares. A refused registration below leaves
        // the bound raised, which only makes a pass visit a record that
        // holds no pin.
        let bound = &self.eras().claimed_bound;
        if bound.load(Ordering::SeqCst) <= index {
            bound.fetch_max(index + 1, Ordering::SeqCst);
        }
        #[cfg(test)]
        if let Ok(Some(interpose)) = INTERPOSE_BEFORE_CUTOFF.try_with(|hook| hook.take()) {
            interpose(self.closed());
        }
        // The cutoff is read after the claim so an admitted registration
        // carries the open-admission witness; a close that landed first
        // takes the record back.
        if self.is_closed() {
            records[index].claimed.store(false, Ordering::Release);
            return Err(RegisterError::Closed);
        }
        Ok(Registration {
            storage: self,
            index,
            record: &records[index],
        })
    }

    /// What record `index` reports, or `None` if it does not exist or the
    /// storage is drained. Pins change without any gate, so the value is a
    /// sample.
    pub fn registration_report(&self, index: RegistrationIndex) -> Option<RegistrationReport> {
        if !self.is_live() {
            return None;
        }
        let record = self.registrations().get(index.0)?;
        let pin = record.pin.load(Ordering::SeqCst);
        Some(RegistrationReport {
            claimed: record.claimed.load(Ordering::Acquire),
            pinned_era: (pin != INACTIVE).then_some(pin),
            intervals: record.intervals.load(Ordering::Relaxed),
        })
    }

    /// Records currently claimed by a registration handle, leaked or not.
    pub(super) fn claimed_registrations(&self) -> usize {
        self.registrations()
            .iter()
            .filter(|record| record.claimed.load(Ordering::Acquire))
            .count()
    }

    /// The era counter and certified era, or `None` once drained.
    pub fn era_report(&self) -> Option<EraReport> {
        if !self.is_live() {
            return None;
        }
        let eras = self.eras();
        let era = eras.era.load(Ordering::SeqCst);
        Some(EraReport {
            era,
            certified: eras.certified.load(Ordering::SeqCst),
            terminal: era >= ERA_TERMINAL,
        })
    }
}

impl<'s, P: Platform> Registration<'s, P> {
    pub fn index(&self) -> RegistrationIndex {
        RegistrationIndex(self.index)
    }

    /// The storage this registration belongs to.
    pub(crate) fn storage(&self) -> &'s Storage<P> {
        self.storage
    }

    #[inline(always)]
    pub(super) fn record(&self) -> &'s RegistrationRecord {
        self.record
    }

    /// Enters one protected interval: `grace::pin` stores the current era
    /// into this record with `SeqCst` once a `Relaxed` load found it
    /// inactive, then the cutoff is read with `SeqCst`, before the holder
    /// observes anything reclaimable.
    ///
    /// # Errors
    ///
    /// `Contended` if the era is terminal, `Leaked` if a forgotten guard
    /// still holds this record's pin, `Closed` if admission closed before
    /// the cutoff read; the record holds no new pin on any of them.
    #[inline(always)]
    pub(crate) fn enter(&mut self) -> Result<Protected<'_, 's, P>, PinError> {
        let record = self.record();
        grace::pin::<_, Sequential>(&self.storage.eras().era, &record.pin).map_err(|refused| {
            match refused {
                PinRefused::Terminal => PinError::Contended,
                PinRefused::Active => PinError::Leaked,
            }
        })?;
        #[cfg(test)]
        if let Ok(Some(interpose)) = INTERPOSE_AFTER_PIN.try_with(|hook| hook.take()) {
            interpose(self.storage.closed());
        }
        // Pin first, cutoff second: both are `SeqCst`, so a cutoff read
        // that returns open places the pin store before the close in the
        // total order, and a pin load ordered after the close sees this pin
        // or, once the interval's protected work has ended, its clearing
        // store. Read the other way round, a close between the two would let
        // that load miss a pin that goes on to observe reclaimable state. A
        // close that landed first takes the pin back before anything is
        // observed under it; nothing was read in between, so the plain
        // clearing store is the whole exit.
        probe::note(Primitive::Load);
        if self.storage.closed().load(Ordering::SeqCst) {
            grace::unpin(&record.pin);
            return Err(PinError::Closed);
        }
        // The handle is the record's only writer of this counter: `enter`
        // takes `&mut self`, and a later claimant of the record acquires
        // the `claimed` release in `Drop`. A load and a store therefore
        // count exactly, without a read-modify-write, and `registration_report`
        // still reads a whole value.
        probe::note(Primitive::Store);
        record.intervals.store(
            record.intervals.load(Ordering::Relaxed).saturating_add(1),
            Ordering::Relaxed,
        );
        Ok(Protected {
            registration: self,
            thread_bound: PhantomData,
        })
    }
}

impl<P: Platform> Drop for Registration<'_, P> {
    fn drop(&mut self) {
        let record = self.record();
        // No interval can be alive here: every `Protected` borrows the
        // handle exclusively, and a leaked guard has no holder left to
        // observe through. The stores below return the record in the state
        // a fresh claimant expects.
        grace::unpin(&record.pin);
        // The record's idle lease credits, in its own word and on its return
        // line, go back to the engine-wide count. A lease of this
        // registration still live returns its credit to the record's return
        // line afterwards, where the next claimant or a reader at the limit
        // takes it.
        let storage = self.storage;
        let lent = drain_record(storage, self.index);
        if lent > 0 {
            let previous = storage.leases().reserved.fetch_sub(lent, Ordering::Release);
            debug_assert!(previous >= lent, "idle credits beyond the reservation");
        }
        record.claimed.store(false, Ordering::Release);
    }
}

#[cfg(test)]
thread_local! {
    /// Runs once between a registration's record claim and its cutoff read
    /// on this thread, so a test can close admission at the last moment.
    pub(crate) static INTERPOSE_BEFORE_CUTOFF: std::cell::Cell<Option<fn(&std::sync::atomic::AtomicBool)>> =
        const { std::cell::Cell::new(None) };

    /// Runs once between an entry's pin store and its cutoff read on this
    /// thread, so a test can close admission under a pin that is already
    /// stored.
    pub(crate) static INTERPOSE_AFTER_PIN: std::cell::Cell<Option<fn(&std::sync::atomic::AtomicBool)>> =
        const { std::cell::Cell::new(None) };
}

impl<'s, P: Platform> Protected<'_, 's, P> {
    /// The era this interval pinned, read back from the record it holds.
    #[cfg(test)]
    pub(crate) fn era(&self) -> u64 {
        self.registration.record().pin.load(Ordering::SeqCst)
    }

    /// The registration this interval pins, for the observations the
    /// interval protects.
    pub(super) fn registration(&mut self) -> &mut Registration<'s, P> {
        self.registration
    }

    /// Ends the interval after the holder's last protected access. Dropping
    /// the guard does the same, which is how the lookup ends its interval.
    #[cfg(test)]
    pub(crate) fn exit(self) {}
}

impl<P: Platform> Drop for Protected<'_, '_, P> {
    #[inline(always)]
    fn drop(&mut self) {
        grace::unpin(&self.registration.record().pin);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::super::config::StorageConfig;
    use super::super::grace::{ERA_FIRST, ERA_TERMINAL};
    use super::super::owner::Storage;
    use super::super::placement::PlacementConfig;
    use super::super::release::Outstanding;
    use super::super::test_platform::TestPlatform;
    use super::{
        EraReport, INTERPOSE_AFTER_PIN, INTERPOSE_BEFORE_CUTOFF, PinError, Protected,
        RegisterError, Registration, RegistrationIndex, RegistrationReport,
    };

    const PAGE: usize = 4096;
    const SLOTS: usize = 4;

    fn storage(slot_count: usize, reader_limit: usize) -> Storage<TestPlatform> {
        let config = StorageConfig {
            page_size: PAGE,
            engine_budget: 1 << 24,
            body_cap: 200,
            metadata_cap: Some(16),
            lease_limit: 8,
            object_rights: 8,
            reader_limit,
            volume: crate::storage::test_volume(slot_count * crate::storage::IO_UNIT, slot_count),
        };
        let placement = PlacementConfig { control_home: 0 };

        Storage::initialize(
            &config.validate().unwrap(),
            &placement,
            TestPlatform::heap(PAGE),
        )
        .unwrap()
    }

    fn report(storage: &Storage<TestPlatform>, index: usize) -> RegistrationReport {
        storage
            .registration_report(RegistrationIndex(index))
            .unwrap()
    }

    fn close(flag: &std::sync::atomic::AtomicBool) {
        flag.store(true, Ordering::SeqCst);
    }

    fn assert_send_sync<T: Send + Sync>() {}

    /// The guard's shape, checked where the compiler can see it: it holds
    /// the registration by exclusive borrow, and it implements neither
    /// `Send` nor `Sync`. Each `AmbiguousIf` lookup compiles only while
    /// exactly one implementation applies, which is the case only when the
    /// guard lacks the marker trait.
    const _: () = {
        fn exclusive<'g, 'r, 's, P: super::Platform>(
            guard: &'g Protected<'r, 's, P>,
        ) -> &'g &'r mut Registration<'s, P> {
            &guard.registration
        }
        let _ = exclusive::<TestPlatform>;

        trait AmbiguousIfSend<A> {
            fn item() {}
        }
        impl<T: ?Sized> AmbiguousIfSend<()> for T {}
        impl<T: ?Sized + Send> AmbiguousIfSend<u8> for T {}
        let _ = <Protected<'static, 'static, TestPlatform> as AmbiguousIfSend<_>>::item;

        trait AmbiguousIfSync<A> {
            fn item() {}
        }
        impl<T: ?Sized> AmbiguousIfSync<()> for T {}
        impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}
        let _ = <Protected<'static, 'static, TestPlatform> as AmbiguousIfSync<_>>::item;
    };

    /// `R` registrations succeed, the next refuses, dropping one returns its
    /// record, and an independent occupancy ledger agrees at every prefix;
    /// registration after close refuses with nothing claimed.
    #[test]
    fn registrations_are_bounded_by_r_returned_on_drop_and_refused_after_close() {
        assert_send_sync::<Registration<'static, TestPlatform>>();
        const R: usize = 3;
        let mut storage = storage(SLOTS, R);
        let root = storage.root_descriptor().unwrap();
        assert_eq!(root.reader_limit, R);
        assert_eq!(storage.registration_report(RegistrationIndex(R)), None);
        let mut handles = Vec::with_capacity(R + 1);
        let allocations = crate::instrument::allocations();
        let mut model = [false; R];
        for expected in 0..R {
            let registration = storage.register().unwrap();
            assert_eq!(registration.index(), RegistrationIndex(expected));
            model[expected] = true;
            handles.push(registration);
            for (index, claimed) in model.iter().enumerate() {
                assert_eq!(
                    report(&storage, index),
                    RegistrationReport {
                        claimed: *claimed,
                        pinned_era: None,
                        intervals: 0,
                    },
                    "{expected} {index}"
                );
            }
            assert_eq!(storage.outstanding().registrations, expected + 1);
        }
        assert_eq!(storage.register().err(), Some(RegisterError::ReaderLimit));
        assert_eq!(crate::instrument::allocations(), allocations);
        assert_eq!(storage.outstanding().registrations, R);

        // Dropping the middle handle frees exactly its record; the next
        // registration takes it.
        drop(handles.swap_remove(1));
        assert!(!report(&storage, 1).claimed);
        assert_eq!(storage.outstanding().registrations, R - 1);
        let again = storage.register().unwrap();
        assert_eq!(again.index(), RegistrationIndex(1));
        handles.push(again);
        assert_eq!(storage.register().err(), Some(RegisterError::ReaderLimit));

        // A leaked handle keeps its record claimed and teardown refused.
        let leaked = handles.pop().unwrap();
        let leaked_index = leaked.index();
        std::mem::forget(leaked);
        drop(handles);
        assert_eq!(
            storage.outstanding(),
            Outstanding {
                registrations: 1,
                ..Outstanding::default()
            }
        );
        assert!(report(&storage, leaked_index.0).claimed);
        assert_eq!(
            super::super::test_platform::blocked(&mut storage).registrations,
            1
        );

        // After close, registration refuses and claims nothing.
        storage.close();
        assert_eq!(storage.register().err(), Some(RegisterError::Closed));
        assert_eq!(storage.outstanding().registrations, 1);
        assert_eq!(crate::instrument::allocations(), allocations);

        // A zero limit admits no reader at all.
        let none = self::storage(SLOTS, 0);
        assert_eq!(none.register().err(), Some(RegisterError::ReaderLimit));
        assert_eq!(none.registration_report(RegistrationIndex(0)), None);
    }

    /// A close that lands between the record claim and the cutoff read gives
    /// the record back: the refusal is `Closed`, nothing stays claimed, and
    /// the outstanding count is unchanged.
    #[test]
    fn a_close_racing_registration_returns_the_claimed_record() {
        let storage = storage(SLOTS, 2);
        let first = storage.register().unwrap();
        INTERPOSE_BEFORE_CUTOFF.with(|hook| hook.set(Some(close)));
        assert_eq!(storage.register().err(), Some(RegisterError::Closed));
        assert!(INTERPOSE_BEFORE_CUTOFF.with(|hook| hook.get().is_none()));
        assert!(storage.is_closed());
        assert!(!report(&storage, 1).claimed);
        assert_eq!(storage.outstanding().registrations, 1);
        drop(first);
        assert_eq!(storage.outstanding().registrations, 0);
    }

    /// A close that lands after the pin store and before the
    /// cutoff read clears the new pin and refuses `Closed`; the interval
    /// is not counted, and entry afterwards refuses the same way with the
    /// record still unpinned.
    #[test]
    fn a_close_racing_entry_clears_the_new_pin() {
        let storage = storage(SLOTS, 1);
        let mut registration = storage.register().unwrap();
        let index = registration.index().0;
        let allocations = crate::instrument::allocations();
        INTERPOSE_AFTER_PIN.with(|hook| hook.set(Some(close)));
        assert_eq!(registration.enter().err(), Some(PinError::Closed));
        assert!(INTERPOSE_AFTER_PIN.with(|hook| hook.get().is_none()));
        assert!(storage.is_closed());
        assert_eq!(
            report(&storage, index),
            RegistrationReport {
                claimed: true,
                pinned_era: None,
                intervals: 0,
            }
        );
        assert_eq!(registration.enter().err(), Some(PinError::Closed));
        assert_eq!(report(&storage, index).pinned_era, None);
        assert_eq!(crate::instrument::allocations(), allocations);
        // The registration and its record are still usable for exit and
        // return: dropping it gives the record back.
        drop(registration);
        assert!(!report(&storage, index).claimed);
    }

    /// The root mapping's extent is the independently placed sum of its
    /// records: with enough 64-byte registration records and their return
    /// lines it spills into a third page, and every record, return line and
    /// the era words sit on a line of their own. The issuance bit follows the cutoff and is counted once;
    /// the bytes it adds to the extent are exactly what the placement says.
    #[test]
    fn registration_records_are_laid_out_one_per_cache_line() {
        use super::super::gate::Gate;
        use super::super::image::{
            EraControls, GraceCursor, LeaseControls, ParkedWord, RegistrationRecord, ReturnLine,
            RootDescriptor,
        };
        let mut end = 0usize;
        let mut place = |size: usize, align: usize, count: usize| {
            let offset = end.next_multiple_of(align);
            end = offset + size * count;
            offset
        };
        place(size_of::<RootDescriptor>(), align_of::<RootDescriptor>(), 1);
        let closed = place(1, 1, 1);
        let issued = place(1, 1, 1);
        assert_eq!(issued, closed + 1);
        let leases = place(size_of::<LeaseControls>(), align_of::<LeaseControls>(), 1);
        const R: usize = 70;
        let parked = place(size_of::<ParkedWord>(), 128, R.div_ceil(64));
        let returns = place(size_of::<ReturnLine>(), 64, R);
        let eras = place(size_of::<EraControls>(), 64, 1);
        let gate = place(size_of::<Gate>(), 128, 1);
        place(size_of::<GraceCursor>(), 64, 1);
        let records = place(size_of::<RegistrationRecord>(), 64, R);
        assert_eq!(size_of::<RegistrationRecord>(), 64);
        assert_eq!(size_of::<ParkedWord>(), 128);
        assert_eq!(size_of::<ReturnLine>(), 64);
        assert_eq!(size_of::<EraControls>(), 64);
        assert_eq!(size_of::<Gate>(), 128);
        assert!(eras.is_multiple_of(64) && gate.is_multiple_of(128) && records.is_multiple_of(64));
        let expected = end.next_multiple_of(PAGE);
        assert_eq!(expected, 3 * PAGE);
        let storage = storage(SLOTS, R);
        assert_eq!(storage.root_extent(), expected);
        assert_eq!(storage.root_image.closed.offset(), closed);
        assert_eq!(storage.root_image.issued.offset(), issued);
        assert_eq!(storage.root_image.leases.offset(), leases);
        assert_eq!(storage.root_image.parked.offset(), parked);
        assert_eq!(storage.parked().len(), 2);
        assert_eq!(storage.root_image.returns.offset(), returns);
        assert_eq!(storage.returns().len(), R);
        // The bit sits in the padding before the 128-byte lease controls,
        // so it adds no byte to the page-rounded extent or the charge; the
        // placement above is the exact accounting.
        assert!(issued < leases);
        let addresses: Vec<usize> = storage
            .registrations()
            .iter()
            .map(|record| record as *const RegistrationRecord as usize)
            .collect();
        assert_eq!(addresses.len(), R);
        assert!(addresses.iter().all(|address| address.is_multiple_of(64)));
        assert!(addresses.windows(2).all(|pair| pair[1] - pair[0] == 64));
        assert_eq!(
            storage.eras() as *const EraControls as usize,
            storage.root.base().as_ptr() as usize + eras
        );
        assert_eq!(
            storage.maintenance_gate() as *const Gate as usize,
            storage.root.base().as_ptr() as usize + gate
        );
    }

    /// A protected interval pins the current era and clears it on exit,
    /// whether by `exit` or by drop, counting one interval each time; the
    /// handle holds no pin between intervals and allocates nothing.
    #[test]
    fn intervals_pin_the_era_and_clear_it_on_exit() {
        let storage = storage(SLOTS, 2);
        let mut registration = storage.register().unwrap();
        let index = registration.index().0;
        let allocations = crate::instrument::allocations();
        assert_eq!(
            storage.era_report(),
            Some(EraReport {
                era: ERA_FIRST,
                certified: 0,
                terminal: false,
            })
        );
        {
            let protected = registration.enter().unwrap();
            assert_eq!(protected.era(), ERA_FIRST);
            assert_eq!(report(&storage, index).pinned_era, Some(ERA_FIRST));
            assert_eq!(report(&storage, index).intervals, 1);
            protected.exit();
        }
        assert_eq!(report(&storage, index).pinned_era, None);
        // The era moves between intervals; the next pin takes the new value.
        storage.eras().era.store(7, Ordering::SeqCst);
        {
            let protected: Protected<'_, '_, TestPlatform> = registration.enter().unwrap();
            assert_eq!(protected.era(), 7);
            assert_eq!(report(&storage, index).pinned_era, Some(7));
        }
        assert_eq!(report(&storage, index).pinned_era, None);
        assert_eq!(report(&storage, index).intervals, 2);
        assert_eq!(crate::instrument::allocations(), allocations);

        // Moving the handle between intervals carries no pin with it.
        let moved = std::thread::scope(|scope| scope.spawn(move || registration).join().unwrap());
        assert_eq!(report(&storage, index).pinned_era, None);
        assert!(report(&storage, index).claimed);
        drop(moved);
        assert!(!report(&storage, index).claimed);
    }

    /// A leaked guard keeps its pin: reentry refuses `Leaked` with the old
    /// pin unchanged and no interval counted, an era change does not move
    /// it, and only destroying the registration clears the record. A fresh
    /// claimant of the same record starts unpinned.
    #[test]
    fn a_leaked_guard_blocks_reentry_until_the_registration_is_destroyed() {
        let storage = storage(SLOTS, 1);
        let mut registration = storage.register().unwrap();
        let index = registration.index().0;
        let leaked = registration.enter().unwrap();
        assert_eq!(leaked.era(), ERA_FIRST);
        std::mem::forget(leaked);
        assert_eq!(report(&storage, index).pinned_era, Some(ERA_FIRST));
        storage.eras().era.store(9, Ordering::SeqCst);
        let allocations = crate::instrument::allocations();
        for _ in 0..3 {
            assert_eq!(registration.enter().err(), Some(PinError::Leaked));
            assert_eq!(
                report(&storage, index),
                RegistrationReport {
                    claimed: true,
                    pinned_era: Some(ERA_FIRST),
                    intervals: 1,
                }
            );
        }
        assert_eq!(crate::instrument::allocations(), allocations);
        drop(registration);
        assert_eq!(
            report(&storage, index),
            RegistrationReport {
                claimed: false,
                pinned_era: None,
                intervals: 1,
            }
        );
        let mut again = storage.register().unwrap();
        assert_eq!(again.index().0, index);
        assert_eq!(again.enter().unwrap().era(), 9);
        assert_eq!(report(&storage, index).intervals, 2);
    }

    /// The interval counter saturates: from `MAX - 1` one entry reaches
    /// `MAX`, and a further entry leaves it there. The counter's value
    /// changes neither the pin nor the era an entry receives.
    #[test]
    fn the_interval_counter_saturates_and_authorizes_nothing() {
        let storage = storage(SLOTS, 1);
        let mut registration = storage.register().unwrap();
        let index = registration.index().0;
        let record = &storage.registrations()[index];
        record.intervals.store(u64::MAX - 1, Ordering::Relaxed);
        {
            let protected = registration.enter().unwrap();
            assert_eq!(protected.era(), ERA_FIRST);
            assert_eq!(report(&storage, index).intervals, u64::MAX);
            assert_eq!(report(&storage, index).pinned_era, Some(ERA_FIRST));
        }
        {
            let protected = registration.enter().unwrap();
            assert_eq!(protected.era(), ERA_FIRST);
            assert_eq!(report(&storage, index).intervals, u64::MAX);
            assert_eq!(report(&storage, index).pinned_era, Some(ERA_FIRST));
        }
        assert_eq!(report(&storage, index).pinned_era, None);
        assert_eq!(report(&storage, index).intervals, u64::MAX);
    }

    /// The terminal era refuses new pins with `Contended`, leaves an existing
    /// pin in place and reports itself; pins below the band still succeed.
    #[test]
    fn the_terminal_era_refuses_new_pins_and_keeps_existing_ones() {
        let storage = storage(SLOTS, 2);
        let mut first = storage.register().unwrap();
        let mut second = storage.register().unwrap();
        let first_index = first.index().0;
        storage.eras().era.store(ERA_TERMINAL - 1, Ordering::SeqCst);
        let held = first.enter().unwrap();
        assert_eq!(held.era(), ERA_TERMINAL - 1);
        storage.eras().era.store(ERA_TERMINAL, Ordering::SeqCst);
        assert!(storage.era_report().unwrap().terminal);
        let allocations = crate::instrument::allocations();
        assert_eq!(second.enter().err(), Some(PinError::Contended));
        assert_eq!(report(&storage, second.index().0).pinned_era, None);
        assert_eq!(report(&storage, second.index().0).intervals, 0);
        assert_eq!(
            report(&storage, first_index).pinned_era,
            Some(ERA_TERMINAL - 1)
        );
        assert_eq!(crate::instrument::allocations(), allocations);
        drop(held);
        assert_eq!(first.enter().err(), Some(PinError::Contended));
    }
}
