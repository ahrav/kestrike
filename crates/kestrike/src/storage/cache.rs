//! The request facade: one non-`Clone` [`Cache`] that borrows the
//! [`Storage`] it serves and is issued at most once.
//!
//! [`Storage`] stays the caller-owned physical domain and the finalization
//! owner. [`Cache::register`] is
//! [`Storage::register`] and [`Cache::lookup`] is [`Registration::lookup`]
//! on a registration of the served storage, so a request path holds one
//! value that names the cache it serves and nothing of the owner's
//! maintenance surface. Registrations and leases borrow the storage, not the
//! facade, so they outlive it: a lease keeps its bytes and a registration
//! keeps its record after the facade is gone.
//!
//! Issuance is one-shot. A fixed bit in the root control mapping, laid out
//! and charged with the rest of the root image, is claimed by one
//! compare-exchange. Issuance on closed or torn-down storage returns
//! `Closed`; a second issuance while otherwise open returns `AlreadyIssued`.
//! No operation clears the bit or reopens admission, and a facade lost to
//! `mem::forget` leaves admission open with no way to issue another.
//!
//! Dropping the facade performs exactly one `SeqCst` store of the admission
//! cutoff, the store [`Storage::close`] makes. It neither waits nor sweeps
//! nor destroys anything: registrations, leases, releases, returns,
//! internal removal, certification and service stay legal after it. The
//! ordering contract of that cutoff, and the list of admission paths that
//! read it, are stated once on [`Storage::close`].
//!
//! Compile-time misuse: the facade cannot be cloned or forged, and the
//! storage cannot be dropped under it.
//!
//! ```compile_fail,E0599
//! # use kestrike::storage::*;
//! # fn f(cache: Cache<'_, LinuxPlatform>) {
//! let copy = cache.clone();
//! # }
//! ```
//!
//! ```compile_fail,E0451
//! # use kestrike::storage::*;
//! # fn f(storage: &Storage<LinuxPlatform>) {
//! let forged = Cache { storage };
//! # }
//! ```
//!
//! ```compile_fail,E0505
//! # use kestrike::storage::*;
//! # fn f(mut storage: Storage<LinuxPlatform>) {
//! let cache = storage.issue_cache().unwrap();
//! drop(storage);
//! let _ = cache.register();
//! # }
//! ```
//!
//! Positive use: the owner first, then the facade; a registered lookup
//! through the facade; the facade dropped while the lease and the
//! registration remain live. The lease stays valid; the next
//! lookup on the surviving registration is refused `Closed`, since the drop
//! closed admission.
//!
//! ```no_run
//! # use kestrike::storage::*;
//! # fn f(storage: &Storage<LinuxPlatform>) -> Result<(), LookupError> {
//! let cache = storage.issue_cache().ok().unwrap();
//! let mut registration = cache.register().ok().unwrap();
//! let mut budget = WorkBudget::new(64);
//! let lease = cache.lookup(&mut registration, &[0x5A; 32], 3, &mut budget)?;
//! drop(cache);
//! let _lease: ExtentLease<'_, LinuxPlatform> = lease;
//! assert_eq!(
//!     registration.lookup(&[0x5A; 32], 3, &mut budget).err(),
//!     Some(LookupError::Closed)
//! );
//! # Ok(())
//! # }
//! ```
//!
//! Stable rustdoc does not check the error codes above; they record the
//! intended cause (E0599 clone, E0451 forged facade, E0505 storage dropped
//! under a facade) for a reader, and `cargo +nightly test --doc` verifies
//! them. The positive example is compile-only; the runtime witnesses are the
//! lookup tests.

use std::sync::atomic::{AtomicBool, Ordering};

use super::budget::WorkBudget;
use super::lease::ExtentLease;
use super::lookup::LookupError;
use super::os::Platform;
use super::owner::Storage;
use super::register::{RegisterError, Registration};
use crate::index::Key;

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "only tests call the entry codec, `merged`, `absorb` and `Fencing::growth`"
    )
)]
pub(crate) mod coverage;

/// Why no facade was issued. `Closed` may leave the issuance bit claimed
/// when the close landed between the claim and its cutoff read; no later
/// call could have claimed it either, since issuance after close is
/// refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheError {
    /// Admission is closed, or the storage has been torn down.
    Closed,
    /// The facade issuance bit was already claimed.
    AlreadyIssued,
}

/// The one request facade over a [`Storage`]. See the module documentation.
#[must_use = "dropping the facade closes admission"]
pub struct Cache<'s, P: Platform> {
    storage: &'s Storage<P>,
}

impl<P: Platform> std::fmt::Debug for Cache<'_, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cache")
            .field("closed", &self.storage.is_closed())
            .finish_non_exhaustive()
    }
}

impl<P: Platform> Storage<P> {
    /// Issues the one facade over this storage. A successful call is a
    /// one-shot claim, and dropping the result closes admission for good;
    /// [`is_issued`](Self::is_issued) is the probe that changes nothing.
    ///
    /// Fixed work: at most two `SeqCst` cutoff loads and one `Relaxed`
    /// compare-exchange of the issuance bit; no allocation and no gate.
    ///
    /// # Errors
    ///
    /// `Closed` if admission is closed or the storage is torn down;
    /// `AlreadyIssued` if the issuance bit was already claimed.
    pub fn issue_cache(&self) -> Result<Cache<'_, P>, CacheError> {
        if !self.is_live() || self.is_closed() {
            return Err(CacheError::Closed);
        }
        // The bit publishes nothing and only its own modification order
        // matters, so the compare-exchange needs no ordering beyond atomicity.
        self.issued()
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .map_err(|_| CacheError::AlreadyIssued)?;
        #[cfg(test)]
        if let Ok(Some(interpose)) = INTERPOSE_AFTER_ISSUE.try_with(|hook| hook.take()) {
            interpose(self.closed());
        }
        // The cutoff is read after the claim so an issued facade carries the
        // open-admission witness, like a registration does. A close that
        // landed between the two reads refuses; the bit stays set, and no
        // later issuance could pass the first read either.
        if self.is_closed() {
            return Err(CacheError::Closed);
        }
        Ok(Cache { storage: self })
    }

    /// The facade issuance bit. Precondition: `is_live()`.
    #[inline(always)]
    fn issued(&self) -> &AtomicBool {
        debug_assert!(self.is_live());
        // SAFETY: the root mapping is owned and the bit was initialized
        // before the owner existed; atomics need no exclusion.
        unsafe { &self.root_image.issued.as_slice(&self.root)[0] }
    }

    /// Whether the issuance bit has been claimed, whether or not a facade
    /// was returned or still exists. `false` once the storage is torn down,
    /// whatever was claimed before.
    pub fn is_issued(&self) -> bool {
        self.is_live() && self.issued().load(Ordering::Relaxed)
    }
}

#[cfg(test)]
thread_local! {
    /// Runs once between the issuance bit's claim and its cutoff read on
    /// this thread, so a test can close admission under a claimed bit.
    pub(crate) static INTERPOSE_AFTER_ISSUE: std::cell::Cell<Option<fn(&AtomicBool)>> =
        const { std::cell::Cell::new(None) };
}

impl<'s, P: Platform> Cache<'s, P> {
    /// The storage this facade serves.
    pub(crate) fn storage(&self) -> &'s Storage<P> {
        self.storage
    }

    /// [`Storage::register`] on the served storage. The registration borrows
    /// the storage, not this facade.
    ///
    /// # Errors
    ///
    /// As for [`Storage::register`].
    pub fn register(&self) -> Result<Registration<'s, P>, RegisterError> {
        self.storage.register()
    }

    /// [`Registration::lookup`] through this facade, on a registration of
    /// the served storage. The lease borrows the storage, not this facade.
    ///
    /// # Panics
    ///
    /// If `registration` belongs to another storage, in every build: domain
    /// identity is equality of the live borrowed owners, and a registration
    /// of one storage looked up through another's facade is a caller error,
    /// not a refusal. The check is one pointer comparison.
    ///
    /// # Errors
    ///
    /// As for [`Registration::lookup`].
    pub fn lookup<'r>(
        &self,
        registration: &mut Registration<'r, P>,
        key: &Key,
        retries: usize,
        budget: &mut WorkBudget,
    ) -> Result<ExtentLease<'r, P>, LookupError> {
        assert!(
            std::ptr::eq(self.storage, registration.storage()),
            "a registration of another storage"
        );
        registration.lookup(key, retries, budget)
    }
}

impl<P: Platform> Drop for Cache<'_, P> {
    fn drop(&mut self) {
        // The borrow proves the storage is live. The cutoff store only: no
        // wait, no sweep, no platform call, no mapping released.
        self.storage.closed().store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::super::budget::WorkBudget;
    use super::super::config::StorageConfig;
    use super::super::owner::Storage;
    use super::super::placement::PlacementConfig;
    use super::super::register::RegisterError;
    use super::super::test_platform::TestPlatform;
    use super::{Cache, CacheError, INTERPOSE_AFTER_ISSUE};

    const PAGE: usize = 4096;
    const SLOTS: usize = 4;

    fn storage(slot_count: usize, platform: TestPlatform) -> Storage<TestPlatform> {
        let config = StorageConfig {
            page_size: PAGE,
            engine_budget: 1 << 24,
            body_cap: 200,
            metadata_cap: Some(16),
            lease_limit: 8,
            object_rights: 8,
            reader_limit: 2,
            volume: crate::storage::test_volume(slot_count * crate::storage::IO_UNIT, slot_count),
        };
        let placement = PlacementConfig { control_home: 0 };

        Storage::initialize(&config.validate().unwrap(), &placement, platform).unwrap()
    }

    fn close(flag: &AtomicBool) {
        flag.store(true, Ordering::SeqCst);
    }

    fn assert_send_sync<T: Send + Sync>() {}

    /// State the facade's drop must leave unchanged, sampled before and
    /// after.
    fn observable(storage: &Storage<TestPlatform>) -> impl PartialEq + std::fmt::Debug {
        (
            storage.era_report(),
            storage.lease_report(),
            storage.outstanding(),
            storage.registration_report(super::super::RegistrationIndex(0)),
            storage.pool_report(),
            storage.engine_used(),
        )
    }

    /// The facade is issued once: the second issuance while open is
    /// `AlreadyIssued`, issuance allocates nothing, and the bit reads set
    /// whether or not the facade still exists.
    #[test]
    fn issuance_is_one_shot_and_allocation_free() {
        assert_send_sync::<Cache<'static, TestPlatform>>();
        let storage = storage(SLOTS, TestPlatform::heap(PAGE));
        assert!(!storage.is_issued());
        let allocations = crate::instrument::allocations();
        let cache = storage.issue_cache().unwrap();
        assert!(storage.is_issued());
        assert_eq!(storage.issue_cache().err(), Some(CacheError::AlreadyIssued));
        assert_eq!(crate::instrument::allocations(), allocations);
        assert!(!storage.is_closed());
        let registration = cache.register().unwrap();
        drop(cache);
        assert!(storage.is_issued());
        assert!(storage.is_closed());
        // The registration outlives the facade and returns its record.
        assert_eq!(storage.outstanding().registrations, 1);
        drop(registration);
        assert_eq!(storage.outstanding().registrations, 0);
    }

    /// Dropping the facade is one cutoff store: admission is closed, no
    /// platform call runs, nothing else observable moves, and closing again
    /// changes nothing. Issuance afterwards is `Closed`, and so is issuance
    /// on storage closed before any facade existed; neither resets the bit
    /// or the cutoff.
    #[test]
    fn dropping_the_facade_closes_admission_once_and_touches_no_mapping() {
        let platform = TestPlatform::heap(PAGE);
        let log = platform.log();
        let storage = storage(SLOTS, platform);
        let cache = storage.issue_cache().unwrap();
        let calls = log.all().len();
        let before = observable(&storage);
        drop(cache);
        assert!(storage.is_closed());
        assert_eq!(observable(&storage), before);
        assert_eq!(log.all().len(), calls);
        assert_eq!(storage.register().err(), Some(RegisterError::Closed));
        assert_eq!(storage.issue_cache().err(), Some(CacheError::Closed));
        storage.close();
        storage.close();
        assert!(storage.is_closed());
        assert!(storage.is_issued());
        assert_eq!(observable(&storage), before);
        assert_eq!(log.all().len(), calls);

        // Closed before any facade: issuance is `Closed` and claims nothing.
        let other = self::storage(SLOTS, TestPlatform::heap(PAGE));
        other.close();
        assert_eq!(other.issue_cache().err(), Some(CacheError::Closed));
        assert!(!other.is_issued());
        assert_eq!(other.issue_cache().err(), Some(CacheError::Closed));
    }

    /// A close that lands between the issuance bit's claim and its cutoff
    /// read refuses `Closed` with the bit left set; the next issuance is
    /// `Closed` as well, so no facade ever comes of the claimed bit.
    #[test]
    fn a_close_racing_issuance_refuses_and_keeps_the_bit() {
        let storage = storage(SLOTS, TestPlatform::heap(PAGE));
        INTERPOSE_AFTER_ISSUE.with(|hook| hook.set(Some(close)));
        assert_eq!(storage.issue_cache().err(), Some(CacheError::Closed));
        assert!(INTERPOSE_AFTER_ISSUE.with(|hook| hook.get().is_none()));
        assert!(storage.is_issued());
        assert!(storage.is_closed());
        assert_eq!(storage.issue_cache().err(), Some(CacheError::Closed));
    }

    /// A forgotten facade never closes admission and can never be
    /// reissued: the bit stays set, registration keeps working, and the
    /// owner's own `close` remains the way to end admission.
    #[test]
    fn a_forgotten_facade_leaves_admission_open_and_unissuable() {
        let storage = storage(SLOTS, TestPlatform::heap(PAGE));
        std::mem::forget(storage.issue_cache().unwrap());
        assert!(storage.is_issued());
        assert!(!storage.is_closed());
        assert_eq!(storage.issue_cache().err(), Some(CacheError::AlreadyIssued));
        let registration = storage.register().unwrap();
        storage.close();
        assert!(storage.is_closed());
        drop(registration);
        assert_eq!(storage.outstanding().registrations, 0);
    }

    /// A registration of one storage looked up through another storage's
    /// facade panics in every build.
    #[test]
    #[should_panic(expected = "a registration of another storage")]
    fn a_registration_of_another_storage_is_refused_by_the_facade() {
        let served = storage(SLOTS, TestPlatform::heap(PAGE));
        let other = self::storage(SLOTS, TestPlatform::heap(PAGE));
        let cache = served.issue_cache().unwrap();
        let mut foreign = other.register().unwrap();
        let _ = cache.lookup(&mut foreign, &[0x5A; 32], 3, &mut WorkBudget::new(64));
    }

    /// Facade loss with live borrowers: registrations taken through the
    /// facade and directly from the storage share the one `R` pool, remain
    /// valid after the facade is dropped and return their records when
    /// dropped.
    #[test]
    fn registrations_outlive_the_facade() {
        let storage = storage(SLOTS, TestPlatform::heap(PAGE));
        let cache = storage.issue_cache().unwrap();
        let through = cache.register().unwrap();
        let direct = storage.register().unwrap();
        assert_eq!(storage.register().err(), Some(RegisterError::ReaderLimit));
        drop(cache);
        assert_eq!(storage.outstanding().registrations, 2);
        drop(through);
        drop(direct);
        assert_eq!(storage.outstanding().registrations, 0);
    }
}
