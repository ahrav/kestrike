//! Each part of an owner stack, built with its budget at its own subtotal,
//! constructs and charges exactly that subtotal; one byte less refuses that
//! part; the envelope admits exactly its total and names the category one
//! byte short reaches; and a subtotal that leaves out the fill tables and
//! follower rows misses the storage's charge.

use crate::storage::owner_fixture::{
    BUFFER, DEPTH, TICK, TestPlatform, arena, device_with, storage_budgeted,
};
use crate::storage::{AttachError, BufferArena, EngineBudget, InitError, StorageCharges, Volume};

use super::activation::{Category, Envelope, EnvelopeError};
use super::link::{Faults, network};
use super::owner::{Bundle, Keys, Owner, OwnerCharges, OwnerError};
use super::owner_tests::{Mux, OWNER, PRINCIPALS, TestOwner, entries, pool};

fn total(charges: StorageCharges) -> usize {
    charges.total().unwrap()
}

fn owner_total(owner: OwnerCharges) -> usize {
    owner.total().unwrap()
}

/// Every part of the owner stack, from storage through owner, built with its
/// budget at the subtotal its charge function names, charges exactly that
/// subtotal; one byte less refuses the part; and the envelope over the parts
/// admits its total and refuses one byte less of each running sum at that
/// sum's category.
#[test]
fn an_exact_envelope_builds_the_stack_and_one_byte_short_names_its_category() {
    let (charges, short) = storage_budgeted(|charges| total(charges) - 1);
    assert!(matches!(
        short.map(|_| ()).unwrap_err().error,
        InitError::Envelope(_)
    ));
    let (charges_again, storage) = storage_budgeted(total);
    assert_eq!(charges_again, charges);
    let storage = storage.unwrap();
    assert_eq!(storage.init_peak(), total(charges), "the startup peak");
    assert_eq!(
        storage.engine_used(),
        charges.root + charges.control + charges.index
    );

    let buffers = arena(16);
    let config = *buffers.config();
    let mut exact = EngineBudget::new(config.charge());
    let other = BufferArena::initialize(&config, TestPlatform::heap(4096), &mut exact);
    assert!(other.is_ok());
    assert_eq!(exact.used(), config.charge());
    let mut short = EngineBudget::new(config.charge() - 1);
    let refused = BufferArena::initialize(&config, TestPlatform::heap(4096), &mut short);
    assert!(matches!(
        refused.map(|_| ()).unwrap_err().error,
        InitError::Envelope(_)
    ));
    drop(other);

    let (disk, _control) = device_with(7, BUFFER);
    let clock = crate::storage::portable::scripted::ScriptedClock::trusted();
    let volume_charge = Volume::attach_charge(
        &storage,
        &buffers,
        &disk,
        &*clock,
        &crate::storage::ServingAuthority::fixture(),
        DEPTH,
        TICK,
    )
    .unwrap();
    let mut short = EngineBudget::new(volume_charge - 1);
    let refused = Volume::attach(
        &storage,
        &buffers,
        disk,
        clock,
        crate::storage::ServingAuthority::fixture(),
        DEPTH,
        TICK,
        &mut short,
    );
    let Err((AttachError::Envelope(_), disk)) = refused.map(|_| ()) else {
        panic!("one byte short refuses the volume");
    };
    let mut exact = EngineBudget::new(volume_charge);
    let volume = Volume::attach(
        &storage,
        &buffers,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        crate::storage::ServingAuthority::fixture(),
        DEPTH,
        TICK,
        &mut exact,
    )
    .map_err(|(error, _)| error)
    .unwrap();
    assert_eq!(exact.used(), volume_charge);

    let owner = TestOwner::charges(&OWNER, &volume, PRINCIPALS.len() as u16).unwrap();
    let receive = pool();
    let started = |budget: &mut EngineBudget, bundle, transport| {
        Owner::start_with_nonce(
            OWNER,
            bundle,
            Keys {
                principals: &PRINCIPALS,
                entries: &entries(),
                epoch: 1,
                put: &PRINCIPALS,
            },
            transport,
            &receive,
            budget,
            |bytes| {
                *bytes = [7; 16];
                Ok(())
            },
        )
    };
    let mut short = EngineBudget::new(owner_total(owner) - 1);
    let cache = storage.issue_cache().unwrap();
    let registration = cache.register().unwrap();
    let bundle = Bundle {
        cache,
        registration,
        volume,
    };
    let mux = || {
        let (_, end0, _) = network(64, 8384, 11, [Faults::default(); 2]);
        let (_, end1, _) = network(64, 8384, 12, [Faults::default(); 2]);
        Mux::new(vec![end0, end1])
    };
    let refused = started(&mut short, bundle, mux()).map(|_| ()).unwrap_err();
    assert!(
        matches!(refused.error, OwnerError::Budget(_)),
        "{:?}",
        refused.error
    );
    assert_eq!(short.used(), 0, "a refused start charges nothing");
    let mut exact = EngineBudget::new(owner_total(owner));
    let transport = mux();
    let live = crate::instrument::live_bytes();
    crate::instrument::reset_peak();
    let built = started(&mut exact, refused.bundle, transport);
    let peak = crate::instrument::peak_bytes().wrapping_sub(live);
    // The owner's heap at its highest during start stays within the bytes
    // it charged, which also count the lookahead and other parts the owner
    // holds inline.
    assert!(
        peak <= owner_total(owner),
        "{peak} heap bytes at start's peak beside {} charged",
        owner_total(owner)
    );
    assert!(built.is_ok());
    assert_eq!(
        exact.used(),
        owner_total(owner),
        "start charges its parts exactly"
    );
    drop(built);

    let envelope = Envelope::new(charges, &config, volume_charge, owner);
    let sum = total(charges) + config.charge() + volume_charge + owner_total(owner);
    assert_eq!(envelope.total(), Ok(sum));
    assert_eq!(envelope.check(sum), Ok(sum));
    assert_eq!(
        envelope.check(sum - 1),
        Err(EnvelopeError::Short {
            category: Category::OwnerPut,
            needed: sum,
            allowance: sum - 1,
        })
    );
    let mut running = 0;
    for category in Category::ALL {
        running += envelope.bytes(category);
        if envelope.bytes(category) > 0 {
            assert!(matches!(
                envelope.check(running - 1),
                Err(EnvelopeError::Short { category: short, .. }) if short == category
            ));
        }
    }
}

#[test]
fn serving_bounds_mismatch_refuses_dry_run_and_attach_without_claiming_or_charging() {
    let (_, storage) = storage_budgeted(total);
    let storage = storage.unwrap();
    let buffers = arena(16);
    let (disk, control) = device_with(7, BUFFER);
    let clock = crate::storage::portable::scripted::ScriptedClock::trusted();
    let bounds = crate::failover::bounds::Bounds::new(8, 1, 1_000, 100, 100, 0).unwrap();
    let other_bounds = crate::failover::bounds::Bounds::new(8, 1, 2_000, 100, 100, 0).unwrap();
    let session = crate::storage::next_session();
    let authority = crate::storage::ServingAuthority::new(
        bounds,
        crate::failover::serving::Machine::new(other_bounds, &session),
        Box::new(crate::storage::BootClock::default()),
        session,
    );
    assert_eq!(
        Volume::attach_charge(&storage, &buffers, &disk, &*clock, &authority, DEPTH, TICK),
        Err(AttachError::AuthorityBounds)
    );
    let mut budget = EngineBudget::new(1 << 24);
    let refused = Volume::attach(
        &storage,
        &buffers,
        disk,
        clock,
        authority,
        DEPTH,
        TICK,
        &mut budget,
    );
    let Err((AttachError::AuthorityBounds, disk)) = refused.map(|_| ()) else {
        panic!("mismatched authority refuses attach");
    };
    assert_eq!(budget.used(), 0);
    assert_eq!(control.accepted(crate::storage::Operation::Read), 0);
    assert_eq!(control.accepted(crate::storage::Operation::Write), 0);
    assert!(
        Volume::attach(
            &storage,
            &buffers,
            disk,
            crate::storage::portable::scripted::ScriptedClock::trusted(),
            crate::storage::ServingAuthority::fixture(),
            DEPTH,
            TICK,
            &mut budget,
        )
        .is_ok()
    );
}

#[test]
fn a_machine_from_another_session_refuses_attach() {
    let (_, storage) = storage_budgeted(total);
    let storage = storage.unwrap();
    let buffers = arena(16);
    let (disk, _control) = device_with(7, BUFFER);
    let clock = crate::storage::portable::scripted::ScriptedClock::trusted();
    let bounds = crate::failover::bounds::Bounds::new(8, 1, 1_000, 100, 100, 0).unwrap();
    let other = crate::storage::next_session();
    let session = crate::storage::next_session();
    assert_ne!(other.target(), session.target());
    let generation = crate::storage::session_at(2, session.target().attempts - 1);
    assert_eq!(
        (generation.target().attempts, generation.epoch()),
        (session.target().attempts, session.epoch())
    );
    for machine_session in [other, generation] {
        let authority = crate::storage::ServingAuthority::new(
            bounds,
            crate::failover::serving::Machine::new(bounds, &machine_session),
            Box::new(crate::storage::BootClock::default()),
            crate::storage::session_at(1, session.target().attempts - 1),
        );
        assert_eq!(
            Volume::attach_charge(&storage, &buffers, &disk, &*clock, &authority, DEPTH, TICK),
            Err(AttachError::AuthoritySession)
        );
    }
}

/// Each part's charges land in their own category: an envelope built from
/// distinct values reads each value back from the category it names.
#[test]
fn each_part_lands_in_its_own_category() {
    let (mut charges, _) = storage_budgeted(total);
    (
        charges.root,
        charges.control,
        charges.index,
        charges.startup,
    ) = (1, 2, 3, 4);
    let config = *arena(16).config();
    let owner = OwnerCharges {
        keys: 7,
        request_table: 8,
        sessions: 9,
        wire_slots: 10,
        serve: 11,
        put: 12,
    };
    let envelope = Envelope::new(charges, &config, 6, owner);
    let expected = [1, 2, 3, 4, config.charge(), 6, 7, 8, 9, 10, 11, 12];
    for (category, bytes) in Category::ALL.into_iter().zip(expected) {
        assert_eq!(envelope.bytes(category), bytes, "{category:?}");
    }
}

/// A resident-only subtotal leaves out the root image, which holds the fill
/// tables and follower rows: the envelope it builds admits its own total,
/// and the storage share that total funds refuses, since initialization
/// still charges the root.
#[test]
fn negative_control_a_resident_only_subtotal_misses_the_fill_rows() {
    let (charges, _) = storage_budgeted(total);
    let resident = StorageCharges { root: 0, ..charges };
    let config = *arena(16).config();
    let none = OwnerCharges {
        keys: 0,
        request_table: 0,
        sessions: 0,
        wire_slots: 0,
        serve: 0,
        put: 0,
    };
    let planted = Envelope::new(resident, &config, 0, none);
    let funded = resident.total().unwrap();
    assert_eq!(planted.total(), Ok(funded + config.charge()));
    let (_, storage) = storage_budgeted(|_| funded);
    assert!(matches!(
        storage.map(|_| ()).unwrap_err().error,
        InitError::Envelope(_)
    ));
}

/// A sum past `usize` refuses `Overflow` at the category that overflowed.
#[test]
fn an_envelope_past_usize_refuses_overflow() {
    let mut bytes = [1; Category::ALL.len()];
    bytes[Category::OwnerServe as usize] = usize::MAX;
    assert_eq!(
        Envelope::of_bytes(bytes).total(),
        Err(EnvelopeError::Overflow {
            category: Category::OwnerServe
        })
    );
}

/// The host's declared owner memory bounds the envelope: a declaration at
/// the total covers it, and one byte less refuses at the last category.
#[test]
fn the_declared_owner_memory_covers_exactly_the_envelope() {
    let bytes = [3; Category::ALL.len()];
    let envelope = Envelope::of_bytes(bytes);
    let total = envelope.total().unwrap();
    let demand = |memory_bytes: usize| super::envelope::OwnerDemand {
        cores: 1,
        memory_bytes: memory_bytes as u64,
        ebs_iops: 0,
        ebs_bytes_per_s: 0,
        network_pps: 0,
    };
    assert_eq!(envelope.covered_by(&demand(total)), Ok(total));
    assert_eq!(
        envelope.covered_by(&demand(total - 1)),
        Err(EnvelopeError::Short {
            category: Category::OwnerPut,
            needed: total,
            allowance: total - 1,
        })
    );
}
