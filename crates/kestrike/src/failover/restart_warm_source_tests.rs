//! A restart carries a warm source exactly when its shard record names a checkpoint.
//!
//! `Restart::run` over the store double and a device double reaches the fencing boundary twice: once over a
//! shard record that names a checkpoint and a cut, where `Restarted::warm()` is `Some` and its `layout()`
//! equals the stored volume record's layout, and once over the same record with no checkpoint, where
//! `Restarted::warm()` is `None`. In both runs every coverage page holds the new session as its fence.

use super::records::{CoveragePage, Layout, NamedCheckpoint, ShardRecord, VolumeRecord};
use super::restart::tests::{
    Card, FULL, restart, sample, shard_now, shard_record, store, volume_id, volume_record,
};
use crate::net::ownership::session_of;
use crate::storage::store::Key;
use crate::storage::store_tests::{client, record as shard_of, shard};

/// The layout the stored volume record carries. It differs from the fixture's (64 units) in its metadata units, so
/// a warm source under any other layout than the stored record's shows.
const STORED: Layout = Layout {
    units: 96,
    slots: 3,
    slot_units: 3,
    entries: 64,
};

/// The stored shard record's `E` before each restart.
const READ_ATTEMPTS: u32 = 2;

/// Bumping the stored record's `E` from [`READ_ATTEMPTS`] activates this session.
fn bumped_session() -> u64 {
    session_of(shard_of().generation.get() as u32, 2 * READ_ATTEMPTS + 2)
}

/// What one restart showed once its fixtures were gone.
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    /// The refusal's check when the restart did not reach the fencing boundary.
    refused: Option<String>,
    /// The device commands the restart issued, in order.
    commands: Vec<&'static str>,
    /// The layout of the warm source the capability carries, when it carries one.
    warm: Option<Layout>,
    /// The layout of the volume record the store holds after the restart.
    stored: Option<Layout>,
    /// The session of the acknowledged bump, and the session the fencing ran under.
    sessions: Option<(u64, u64)>,
    /// Whether the fencing holds its coverage.
    covered: bool,
    /// The fence each coverage page of the bumped record holds in the store.
    fences: Vec<u64>,
    /// The checkpoint and cut the shard record names after the bump.
    names: (Option<NamedCheckpoint>, u64),
}

/// The checkpoint the warm record names: slot 1, captured by a session of the record's generation.
fn named() -> NamedCheckpoint {
    NamedCheckpoint {
        slot: 1,
        session: session_of(shard_of().generation.get() as u32, 4),
        capture: 3,
        units: 2,
    }
}

/// Runs one restart over a store that holds `record` and a volume record under [`STORED`], with the device double
/// and the sample local record, and reads what it left: the capability's warm source, the fencing and the pages.
fn restarted_over(record: ShardRecord) -> Seen {
    let volume = VolumeRecord {
        layout: STORED,
        ..volume_record()
    };
    let store = store(record, volume);
    let mut card = Card::new();
    let outcome = restart().run(&mut client(&store), &sample(), &mut card);
    let bumped = shard_now(&store);
    let fences = (0..bumped.pages.get())
        .map(|page| {
            client(&store)
                .read::<CoveragePage>(Key::Page(shard(), page))
                .map_or(u64::MAX, |read| read.value().fence)
        })
        .collect();
    let stored = client(&store)
        .read::<VolumeRecord>(Key::Volume(volume_id()))
        .ok()
        .map(|read| read.value().layout);
    let restarted = outcome.as_ref().ok();
    let seen = Seen {
        refused: outcome
            .as_ref()
            .err()
            .map(|refused| format!("{:?}", refused.check)),
        commands: card.log.clone(),
        warm: restarted.and_then(|restarted| restarted.warm().map(|source| *source.layout())),
        stored,
        sessions: restarted
            .map(|restarted| (restarted.session().get(), restarted.fencing().session())),
        covered: restarted.is_some_and(|restarted| restarted.fencing().coverage().is_some()),
        fences,
        names: (bumped.checkpoint, bumped.cut),
    };
    drop(outcome);
    drop(card);
    drop(store);
    seen
}

/// What both restarts must show apart from the warm source: the capability, every device step, and every coverage
/// page fenced under the new session.
fn fenced_under_the_new_session(seen: &Seen) -> Result<u64, String> {
    if let Some(check) = &seen.refused {
        return Err(format!("the restart refused at {check}"));
    }
    if seen.commands != FULL {
        return Err(format!("the device steps were {:?}", seen.commands));
    }
    let Some((session, fencing)) = seen.sessions else {
        return Err("the restart returned no session".to_owned());
    };
    if fencing != session {
        return Err(format!(
            "the fencing ran under {fencing}, the session is {session}"
        ));
    }
    if !seen.covered {
        return Err("the fencing holds no coverage".to_owned());
    }
    if seen.fences.is_empty() || seen.fences.iter().any(|fence| *fence != session) {
        return Err(format!(
            "the pages hold fences {:?}, the session is {session}",
            seen.fences
        ));
    }
    if seen.stored != Some(STORED) {
        return Err(format!("the store holds the layout {:?}", seen.stored));
    }
    Ok(session)
}

/// A restart whose acknowledged shard record names a checkpoint carries a warm source under the volume
/// record's layout. The record names slot 1 and cut 5; the restart reaches the fencing boundary, fences every page
/// under its new session, and its capability carries a source whose layout is the stored volume record's.
#[test]
fn a_restart_over_a_record_naming_a_checkpoint_carries_a_warm_source_under_the_stored_layout() {
    let seen = restarted_over(ShardRecord {
        checkpoint: Some(named()),
        cut: 5,
        ..shard_record(READ_ATTEMPTS)
    });
    assert_eq!(fenced_under_the_new_session(&seen), Ok(bumped_session()));
    assert_eq!(
        seen.names,
        (Some(named()), 5),
        "premise: the bumped record still names the checkpoint and the cut"
    );
    assert_eq!(
        seen.warm,
        Some(STORED),
        "the capability carries a warm source under the stored volume record's layout"
    );
}

/// The same restart over the same record with no checkpoint reaches the same boundary, fences every
/// page under its new session, and carries no warm source, so the tenure starts cold.
#[test]
fn the_same_restart_over_a_record_naming_no_checkpoint_carries_no_warm_source() {
    let seen = restarted_over(shard_record(READ_ATTEMPTS));
    assert_eq!(fenced_under_the_new_session(&seen), Ok(bumped_session()));
    assert_eq!(
        seen.names,
        (None, shard_record(READ_ATTEMPTS).cut),
        "premise: the record names no checkpoint"
    );
    assert_eq!(
        seen.warm, None,
        "a record naming no checkpoint gives no warm source"
    );
}
