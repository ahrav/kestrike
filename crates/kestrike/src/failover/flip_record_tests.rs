//! A flip maps a shard record to exactly the record of the next generation under the spare.
//!
//! A shard record at generation g with `E = 1`, a spare on another host, a standby, a named checkpoint with a
//! nonzero cut and a nonempty ancestry is flipped. `flipped` returns exactly the record of g + 1 whose active
//! volume and owner are the spare's, with `E = 0`, no spare, no standby, no checkpoint, cut 0 and the empty
//! ancestry, and the input's shard, `B`, `C_page` and namespace. The refusals follow: `NoSpare` without a
//! spare and for a spare that is the active volume, `GenerationExhausted` at g = 2^32 - 2 and 2^32 - 1, a
//! flip from 2^32 - 3 to 2^32 - 2, and `NoSpare` when both refusals apply. The store half writes the same
//! populated record, flips it through `Client::flip` and reads that value back from the store. The last test
//! flips the fixture's plain record, which has nothing to clear, and shows that the populated input differs
//! from it in every field the flip clears.

use super::flip::{FlipRefusal, flipped};
use super::records::{Ancestry, Host, NamedCheckpoint, ShardRecord, Suffix, VolumeId};
use crate::net::ownership::ShardGeneration;
use crate::storage::store::sim::Shared;
use crate::storage::store::{Key, StoreError};
use crate::storage::store_tests::{OWNER, SPARE, client, record, shard, stored};

/// A host that is neither the fixture's owner nor its spare's host.
const STANDBY: u64 = 13;

fn generation(value: u64) -> ShardGeneration {
    ShardGeneration::new(value).unwrap()
}

/// The fixture record with a value in every field a flip clears: `E = 1`, a standby, a named checkpoint of the
/// record's own generation, a nonzero cut and one ancestry suffix.
fn populated() -> ShardRecord {
    let base = record();
    let named = NamedCheckpoint {
        slot: 1,
        session: (base.generation.get() << 32) | 2,
        capture: 1,
        units: 4,
    };
    ShardRecord {
        attempts: 1,
        checkpoint: Some(named),
        cut: 9,
        ancestry: Ancestry::new(&[Suffix {
            session: named.session,
            start: 9,
            certified: 12,
            end: 12,
        }])
        .unwrap(),
        standby: Some(Host::new(STANDBY).unwrap()),
        ..base
    }
}

/// The record expected of a flip of `read` to the spare `(volume, host)`, every field written out.
fn expected(read: &ShardRecord, (volume, host): (VolumeId, Host)) -> ShardRecord {
    ShardRecord {
        shard: read.shard,
        generation: generation(read.generation.get() + 1),
        active: volume,
        owner: host,
        attempts: 0,
        spare: None,
        checkpoint: None,
        cut: 0,
        pages: read.pages,
        page_cap: read.page_cap,
        namespace: read.namespace,
        ancestry: Ancestry::default(),
        standby: None,
    }
}

#[test]
fn a_flip_of_a_populated_record_writes_the_next_generation_with_every_tenure_field_cleared() {
    let read = populated();
    let spare = read.spare.expect("premise: the fixture names a spare");
    // Premises: the input holds a value in every field the flip clears, and its spare is another volume on
    // another host, so a result equal to `expected` shows each clearing and each move.
    assert!(read.attempts > 0, "premise: E > 0");
    assert!(read.standby.is_some(), "premise: a standby");
    assert!(read.checkpoint.is_some(), "premise: a named checkpoint");
    assert!(read.cut > 0, "premise: a nonzero cut");
    assert_ne!(read.ancestry, Ancestry::default(), "premise: an ancestry");
    assert_ne!(spare.0, read.active, "premise: the spare is another volume");
    assert_ne!(spare.1, read.owner, "premise: the spare is on another host");
    assert_eq!(
        (spare.1.get(), read.owner.get(), read.generation.get()),
        (SPARE, OWNER, 3),
        "premise: the fixture's owner, spare host and generation"
    );

    let wanted = expected(&read, spare);
    assert_eq!(
        flipped(&read),
        Ok(wanted),
        "(g, V_g, owner, E) flips to (g + 1, V_s, spare host, 0) with no spare, standby, checkpoint, \
         cut or ancestry, and the shard, B, C_page and namespace carried over"
    );
    assert_eq!(
        (wanted.generation.get(), wanted.active, wanted.owner.get()),
        (4, VolumeId::new("vol-0b").unwrap(), SPARE),
        "the expected record names generation g + 1 and the spare"
    );
}

#[test]
fn a_flip_refuses_no_spare_before_an_exhausted_generation() {
    let last = u64::from(u32::MAX);
    let at = |g: u64| ShardRecord {
        generation: generation(g),
        ..populated()
    };
    let spare = populated().spare.unwrap();

    let none = ShardRecord {
        spare: None,
        ..populated()
    };
    assert_eq!(
        flipped(&none),
        Err(FlipRefusal::NoSpare),
        "a record without a spare refuses NoSpare"
    );
    let own = ShardRecord {
        spare: Some((populated().active, spare.1)),
        ..populated()
    };
    assert_eq!(
        flipped(&own),
        Err(FlipRefusal::NoSpare),
        "a spare that is the active volume is no spare"
    );

    assert_eq!(
        flipped(&at(last - 2)),
        Ok(expected(&at(last - 2), spare)),
        "g = 2^32 - 3 flips to 2^32 - 2, the last generation a session activates"
    );
    assert_eq!(
        flipped(&at(last - 2)).map(|next| next.generation.get()),
        Ok(last - 1)
    );
    assert_eq!(
        flipped(&at(last - 1)),
        Err(FlipRefusal::GenerationExhausted),
        "g + 1 = 2^32 - 1 refuses GenerationExhausted"
    );
    assert_eq!(
        flipped(&at(last)),
        Err(FlipRefusal::GenerationExhausted),
        "g = 2^32 - 1 refuses GenerationExhausted"
    );

    for g in [last - 1, last] {
        let both = ShardRecord {
            spare: None,
            ..at(g)
        };
        assert_eq!(
            flipped(&both),
            Err(FlipRefusal::NoSpare),
            "NoSpare comes before GenerationExhausted at g = {g}"
        );
        let both = ShardRecord {
            spare: Some((at(g).active, spare.1)),
            ..at(g)
        };
        assert_eq!(
            flipped(&both),
            Err(FlipRefusal::NoSpare),
            "NoSpare comes before GenerationExhausted at g = {g} for a spare that is the active volume"
        );
    }
}

#[test]
fn a_flip_through_the_client_leaves_the_flipped_record_in_the_store() {
    let read_value = populated();
    let spare = read_value.spare.unwrap();
    // Everything the store and its clients hold is read into values before the first assertion.
    let (before, flip, after, refusal) = {
        let store = Shared::new();
        let mut reconciler = client(&store);
        reconciler.create_shard(read_value).unwrap();
        let before = stored(&store).1;
        let read = reconciler.read::<ShardRecord>(Key::Shard(shard())).unwrap();
        let flip = reconciler
            .flip(&read)
            .map(|flipped| (flipped.shard(), flipped.generation()));
        let after = stored(&store).1;
        // The flipped record names no spare, so a second flip of it refuses before any request.
        let again = reconciler.read::<ShardRecord>(Key::Shard(shard())).unwrap();
        let refusal = reconciler.flip(&again).err();
        (before, flip, after, refusal)
    };
    assert_eq!(
        before, read_value,
        "premise: the store holds the populated record"
    );
    assert_eq!(
        after,
        expected(&read_value, spare),
        "Client::flip leaves flipped's record in the store"
    );
    assert_eq!(
        flip,
        Ok((shard(), generation(read_value.generation.get() + 1))),
        "the flip reports the shard and generation g + 1"
    );
    assert_eq!(
        refusal,
        Some(StoreError::Flip(FlipRefusal::NoSpare)),
        "the flipped record names no spare"
    );
}

#[test]
fn a_flip_of_the_plain_fixture_has_nothing_to_clear() {
    // The fixture's own record, with E = 0 and no standby, checkpoint, cut or ancestry, flips to
    // the same value as the populated one, so the populated input is what shows the clearing.
    let plain = record();
    let spare = plain.spare.unwrap();
    assert_eq!(
        (
            plain.attempts,
            plain.standby,
            plain.checkpoint,
            plain.cut,
            plain.ancestry
        ),
        (0, None, None, 0, Ancestry::default()),
        "premise: the plain fixture holds the cleared value in every field a flip clears"
    );
    assert_eq!(flipped(&plain), Ok(expected(&plain, spare)));
    assert_eq!(flipped(&plain), flipped(&populated()));
}
