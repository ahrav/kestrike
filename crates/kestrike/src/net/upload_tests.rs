use std::cell::{Cell, RefCell};
use std::rc::Rc;

use crate::sim::round::Actor;
use crate::storage::owner_fixture::{SimControl, arena, arena_sized, write_tokens};
use crate::storage::{CacheVersion, EngineBudget, PoolKind};

use super::auth::KeyRing;
use super::client::{
    Client, ClientConfig, GetRefused, PutRefused, Staged, seal_data, yields_a_frame,
};
use super::client_namespace::ClientRequests;
use super::datagram::HEADER_LEN;
use super::datagram::PeerId;
use super::fetch::{FetchConfig, FetchCoreError, Releases};
use super::frame::Status;
use super::frame::{Direction, Header, Kind, encode_with_body_crc, parse};
use super::link::{Faults, LinkEnd, Net, TxRelease};
use super::memory::{SourcesError, sources};
use super::owner::OwnerConfig;
use super::owner_tests::{PRINCIPALS, entries, key, payload};
use super::put_tests::{Scene, request, scene, scene_with_client};
use super::requests::{RequestId, RequestTable};
use super::rules::{Chain, Effect, MANIFEST, Rule, Selector};
use super::serve::ServeConfig;
use super::serve::header;
use super::session::{Admitted, Caps};
use super::upload::{PrepareRefused, SupplyRefused, UploadOutcome};
use super::upload::{UploadConfig, UploadCore};
use crate::storage::Crc32c;
use crate::storage::Operation;
use crate::storage::device::sim::{Event, Fault};

const TTL_MS: u32 = 60_000;

use super::adapters::{FRAGMENT, drive, drive_then, shaped, upload};

fn held(scene: &Scene<'_, '_>) -> usize {
    scene.clients[0]
        .sources()
        .iter()
        .filter(|slot| slot.piece().is_some())
        .count()
}

#[test]
fn input_waits_for_authority_and_ready() {
    input_waits(false);
}

/// The control for input before READY: the owner's READY arrives between the PREPARE and the supply, so the
/// supply that the test makes before READY is accepted, as an upload that took input after PREPARE would accept it.
#[test]
#[should_panic(expected = "input after PREPARE and before READY is refused NotReady")]
fn negative_control_a_ready_delivered_before_the_supply_admits_the_input() {
    input_waits(true);
}

/// When `ready_first` is set, four turns deliver the owner's READY before the third `supply`. That call returns
/// `Ok(8192)`, so the `NotReady` assertion gives the control its expected panic.
fn input_waits(ready_first: bool) {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(3 * 8192 - 100, 30);
        let now = scene.turn * 100;
        let id = scene.clients[0]
            .put(key(6), CacheVersion(0), now, 30_000_000)
            .unwrap();
        assert_eq!(
            scene.clients[0].prepare(id, 0, object.len() as u32, TTL_MS),
            Err(PrepareRefused::Phase)
        );
        assert_eq!(
            scene.clients[0].supply(id, 0, &object[..8192]),
            Err(SupplyRefused::NotReady)
        );
        drive(&mut scene, 4);
        let client = &mut scene.clients[0];
        assert_eq!(
            client.prepare(id, 0, object.len() as u32, 0),
            Err(PrepareRefused::Ttl)
        );
        assert_eq!(
            client.supply(id, 0, &object[..8192]),
            Err(SupplyRefused::NotReady)
        );
        client.prepare(id, 0, object.len() as u32, TTL_MS).unwrap();
        assert_eq!(
            client.prepare(id, 0, object.len() as u32 + 1, TTL_MS),
            Err(PrepareRefused::Mismatch)
        );
        client.prepare(id, 0, object.len() as u32, TTL_MS).unwrap();
        if ready_first {
            drive(&mut scene, 4);
        }
        let supplied = scene.clients[0].supply(id, 0, &object[..8192]);
        if ready_first {
            assert_eq!(
                supplied,
                Ok(8192),
                "the READY delivered first lets the supply take the fragment"
            );
        }
        assert_eq!(
            supplied,
            Err(SupplyRefused::NotReady),
            "input after PREPARE and before READY is refused NotReady"
        );
        assert_eq!(held(&scene), 0);
        drive(&mut scene, 4);
        let client = &mut scene.clients[0];
        assert_eq!(
            client.supply(id, 3, &object[..1]),
            Err(SupplyRefused::Index)
        );
        assert_eq!(
            client.supply(id, 2, &object[..8192]),
            Err(SupplyRefused::Length)
        );
        assert_eq!(client.supply(id, 2, &object[16384..]), Ok(8092));
        assert_eq!(
            client.supply(id, 2, &object[16384..]),
            Err(SupplyRefused::Index)
        );
        assert_eq!(client.supply(id, 0, &object[..8192]), Ok(8192));
        let pieces: Vec<_> = client
            .sources()
            .iter()
            .filter_map(|slot| slot.piece())
            .map(|piece| piece.bytes().to_vec())
            .collect();
        assert_eq!(pieces, [object[16384..].to_vec(), object[..8192].to_vec()]);
        assert_eq!(client.put_outcome(id), None);
    });
}

#[test]
fn a_zero_byte_upload_publishes_after_its_header_write() {
    scene(&PRINCIPALS, |mut scene| {
        let now = scene.turn * 100;
        let id = scene.clients[0]
            .put(key(6), CacheVersion(0), now, 30_000_000)
            .unwrap();
        drive(&mut scene, 4);
        scene.clients[0].prepare(id, 0, 0, TTL_MS).unwrap();
        drive(&mut scene, 10);
        assert_eq!(
            scene.clients[0].put_outcome(id),
            Some(UploadOutcome::Published)
        );
        assert!(scene.clients[0].retire(id));
        assert_eq!(held(&scene), 0);
    });
}

#[test]
fn a_refused_permission_starts_no_source_work() {
    scene(&PRINCIPALS[1..], |mut scene| {
        let now = scene.turn * 100;
        let id = scene.clients[0]
            .put(key(6), CacheVersion(0), now, 30_000_000)
            .unwrap();
        drive(&mut scene, 6);
        let client = &mut scene.clients[0];
        assert_eq!(
            client.put_outcome(id),
            Some(UploadOutcome::Failed(Status::PermissionDenied))
        );
        assert_eq!(client.prepare(id, 0, 1, TTL_MS), Err(PrepareRefused::Phase));
        assert_eq!(client.supply(id, 0, &[1]), Err(SupplyRefused::NotReady));
        assert_eq!(held(&scene), 0);
    });
}

#[test]
fn a_begin_never_handed_to_send_has_not_started() {
    scene(&PRINCIPALS, |mut scene| {
        let now = scene.turn * 100;
        let id = scene.clients[0]
            .put(key(6), CacheVersion(0), now, 1_000)
            .unwrap();
        scene.clients[0].poll(now + 1_000);
        assert_eq!(
            scene.clients[0].put_outcome(id),
            Some(UploadOutcome::NotStarted)
        );
        assert!(scene.clients[0].retire(id));
    });
}

#[test]
fn a_silent_owner_after_a_possible_send_is_unknown() {
    scene(&PRINCIPALS, |mut scene| {
        let now = scene.turn * 100;
        let id = scene.clients[0]
            .put(key(6), CacheVersion(0), now, 50_000)
            .unwrap();
        for turn in 0..1_000 {
            scene.clients[0].poll(now + turn * 100);
        }
        assert_eq!(
            scene.clients[0].put_outcome(id),
            Some(UploadOutcome::Unknown)
        );
    });
}

#[test]
fn puts_beyond_the_request_slots_are_refused() {
    scene(&PRINCIPALS, |mut scene| {
        let now = scene.turn * 100;
        let mut admitted = Vec::new();
        while let Ok(id) = scene.clients[0].put(key(6), CacheVersion(0), now, 30_000_000) {
            admitted.push(id);
        }
        assert_eq!(
            scene.clients[0].put(key(6), CacheVersion(0), now, 30_000_000),
            Err(PutRefused::RequestPressure)
        );
        assert_eq!(admitted.len(), 3);
    });
}

#[test]
fn a_source_refusal_returns_every_acquired_buffer() {
    let shared = arena(8);
    let taken = shared.acquire(PoolKind::ReadResponse).unwrap();
    let mut budget = EngineBudget::new(1 << 20);
    let before = budget;
    assert_eq!(
        sources(&shared, 8, &mut budget).err(),
        Some(SourcesError::Exhausted)
    );
    assert_eq!(budget, before);
    drop(taken);
    let kept = sources(&shared, 8, &mut budget).unwrap();
    assert_eq!(kept.len(), 8);
    drop(kept);
    assert_eq!(
        sources(&shared, 9, &mut budget).err(),
        Some(SourcesError::Count)
    );
    let small = arena_sized(2, 4096);
    assert_eq!(
        sources(&small, 2, &mut budget).err(),
        Some(SourcesError::Capacity)
    );
    let mut short = EngineBudget::new(1);
    assert!(matches!(
        sources(&shared, 8, &mut short),
        Err(SourcesError::Budget(_))
    ));
    assert_eq!(sources(&shared, 8, &mut budget).unwrap().len(), 8);
}

/// A `u16` holds all 65,536 slot indices `sources` admits; their count requires a wider integer.
#[test]
fn the_largest_source_count_starts_with_every_slot_free() {
    const COUNT: u32 = 1 << 16;
    let shared = arena_sized(COUNT, 8192);
    let mut budget = EngineBudget::new(1 << 30);
    let slots = sources(&shared, COUNT, &mut budget).unwrap();
    assert_eq!(slots.len(), COUNT as usize);
    let releases = Releases::new(4, &mut budget).unwrap();
    let mut requests =
        ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let config = UploadConfig {
        retry_us: 1_000,
        attempts: 3,
    };
    let mut core = UploadCore::new(config, slots, &mut requests, &mut budget).unwrap();
    let id = ready(&mut core, &mut requests, 6, 3);
    let object = payload(8192, 97);
    assert_eq!(core.supply(&mut requests, id, 0, &object), Ok(8192));
}

#[test]
fn a_slot_stays_held_until_its_device_reference_ends() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(8192, 31);
        let now = scene.turn * 100;
        let id = scene.clients[0]
            .put(key(6), CacheVersion(0), now, 3_000)
            .unwrap();
        drive(&mut scene, 4);
        scene.clients[0].prepare(id, 0, 8192, TTL_MS).unwrap();
        drive(&mut scene, 4);
        assert_eq!(scene.clients[0].supply(id, 0, &object), Ok(8192));
        let hold = scene.clients[0]
            .sources()
            .iter()
            .find_map(|slot| slot.piece())
            .unwrap()
            .hold()
            .unwrap();
        drive(&mut scene, 40);
        assert_eq!(
            scene.clients[0].put_outcome(id),
            Some(UploadOutcome::Published)
        );
        assert!(
            !scene.clients[0].retire(id),
            "a device-held slot keeps its upload"
        );
        assert_eq!(held(&scene), 1);
        drop(hold);
        drive(&mut scene, 1);
        assert!(scene.clients[0].retire(id));
        assert_eq!(held(&scene), 0);
    });
}

#[test]
fn steady_state_upload_calls_allocate_nothing() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(8192, 32);
        let mut allocations = 0;
        for round in 0..3u8 {
            let before = crate::instrument::allocations();
            let now = scene.turn * 100;
            let id = scene.clients[0]
                .put(key(20 + round), CacheVersion(0), now, 3_000)
                .unwrap();
            allocations += crate::instrument::allocations() - before;
            let mut ready = false;
            for _ in 0..60 {
                scene.turn_with(&mut [(Actor::Client(0), &mut |clients, _, now| {
                    let before = crate::instrument::allocations();
                    clients[0].poll(now);
                    ready = ready
                        || clients[0].prepare(id, 0, 8192, TTL_MS).is_ok()
                            && clients[0].supply(id, 0, &object).is_ok();
                    let _ = clients[0].put_outcome(id);
                    allocations += crate::instrument::allocations() - before;
                })]);
            }
            assert!(ready, "round {round}");
            let before = crate::instrument::allocations();
            assert!(scene.clients[0].retire(id));
            allocations += crate::instrument::allocations() - before;
            drive(&mut scene, 20);
        }
        assert_eq!(allocations, 0);
    });
}

const SESSION: Admitted = Admitted {
    peer: PeerId(0),
    epoch: 1,
    caps: Caps {
        slots: 4,
        window: 4,
    },
};

fn sent(core: &mut UploadCore<'_>, requests: &mut ClientRequests<'_>, now_us: u64) -> Vec<Kind> {
    let mut kinds = Vec::new();
    core.poll(requests, now_us, 8, |_, header| {
        kinds.push(header.kind);
        true
    });
    kinds
}

fn reply(
    id: RequestId,
    requests: &ClientRequests<'_>,
    kind: Kind,
    edit: impl FnOnce(&mut Header),
) -> Header {
    let upload = requests.upload(id).unwrap();
    let (wire, key) = (upload.wire(), upload.key());
    // READY, ACK and RESULT carry the prepared manifest, as the owner sends them.
    let mut reply = match (kind, upload.prepared()) {
        (Kind::PutReady | Kind::PutAck | Kind::PutResult, Some((metadata_len, body_len))) => {
            let manifest = super::serve::Manifest {
                allocation: 5,
                metadata_len,
                body_len,
            };
            super::serve::manifest_header(kind, wire, key, &manifest)
        }
        _ => Header {
            allocation: 5,
            ..header(kind, wire, key)
        },
    };
    edit(&mut reply);
    reply
}

#[test]
fn a_full_receipt_awaits_the_result_with_its_retry_armed() {
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut budget = EngineBudget::new(1 << 20);
    let mut requests =
        ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let config = UploadConfig {
        retry_us: 1_000,
        attempts: 3,
    };
    let mut core = UploadCore::new(config, Box::default(), &mut requests, &mut budget).unwrap();
    let id = core
        .put(
            &mut requests,
            SESSION,
            key(6),
            CacheVersion(0),
            0,
            1_000_000,
        )
        .unwrap();
    assert_eq!(sent(&mut core, &mut requests, 0), [Kind::PutBegin]);
    let authority = reply(id, &requests, Kind::PutAuthority, |_| {});
    assert!(core.receive(&mut requests, SESSION, &authority, 10));
    core.prepare(&mut requests, id, 0, 3 * 8192, TTL_MS)
        .unwrap();
    assert_eq!(sent(&mut core, &mut requests, 20), [Kind::PutPrepare]);
    let stale = reply(id, &requests, Kind::PutReady, |reply| reply.allocation = 9);
    assert!(!core.receive(&mut requests, SESSION, &stale, 30));
    let elsewhere = Admitted {
        epoch: 2,
        ..SESSION
    };
    let ready = reply(id, &requests, Kind::PutReady, |reply| reply.grant = 3);
    assert!(!core.receive(&mut requests, elsewhere, &ready, 30));
    assert!(core.receive(&mut requests, SESSION, &ready, 30));
    let full = reply(id, &requests, Kind::PutAck, |reply| {
        reply.index = 3;
        reply.grant = 3;
    });
    assert!(core.receive(&mut requests, SESSION, &full, 40));
    assert_eq!(
        core.outcome(&requests, id),
        None,
        "full receipt is not success"
    );
    core.tick(&mut requests, 500);
    assert!(sent(&mut core, &mut requests, 500).is_empty());
    core.tick(&mut requests, 1_040);
    assert_eq!(sent(&mut core, &mut requests, 1_040), [Kind::PutPrepare]);
    let unknown = reply(id, &requests, Kind::PutError, |reply| {
        reply.status = Status::UnknownOutcome as u16
    });
    assert!(core.receive(&mut requests, SESSION, &unknown, 1_100));
    assert_eq!(core.outcome(&requests, id), Some(UploadOutcome::Unknown));
    let result = reply(id, &requests, Kind::PutResult, |_| {});
    assert!(core.receive(&mut requests, SESSION, &result, 1_200));
    assert_eq!(core.outcome(&requests, id), Some(UploadOutcome::Published));
}

/// A namespace serves one upload core: a second `new` over it is refused as `Paired` with the budget unchanged, and the first core keeps working.
#[test]
fn a_second_upload_core_is_refused() {
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut budget = EngineBudget::new(1 << 20);
    let mut requests =
        ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let config = UploadConfig {
        retry_us: 1_000,
        attempts: 3,
    };
    let mut first = UploadCore::new(config, Box::default(), &mut requests, &mut budget).unwrap();
    let mut untouched = EngineBudget::new(1 << 20);
    let second = UploadCore::new(config, Box::default(), &mut requests, &mut untouched);
    assert!(matches!(second, Err(FetchCoreError::Paired)));
    assert_eq!(untouched, EngineBudget::new(1 << 20));
    first
        .put(
            &mut requests,
            SESSION,
            key(6),
            CacheVersion(0),
            0,
            1_000_000,
        )
        .unwrap();
}

/// An upload core runs over the namespace it was built from; another namespace, even one with more slots than the core's indexes, is refused before any index is read.
#[test]
#[should_panic(expected = "an upload core runs over the namespace it was built from")]
fn an_upload_core_refuses_another_namespace() {
    let board = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let other = Releases::new(8, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut budget = EngineBudget::new(1 << 20);
    let mut ours = ClientRequests::new(RequestTable::new(4, 1, 4), &board, &mut budget).unwrap();
    let mut theirs = ClientRequests::new(RequestTable::new(8, 1, 8), &other, &mut budget).unwrap();
    let config = UploadConfig {
        retry_us: 1_000,
        attempts: 3,
    };
    let mut core = UploadCore::new(config, Box::default(), &mut ours, &mut budget).unwrap();
    core.tick(&mut theirs, 0);
}

/// A PUT reply names its request's key, so a late reply to an earlier request that held this wire slot under another key leaves the upload in its phase.
#[test]
fn a_reply_naming_another_key_is_ignored() {
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut budget = EngineBudget::new(1 << 20);
    let mut requests =
        ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let config = UploadConfig {
        retry_us: 1_000,
        attempts: 3,
    };
    let mut core = UploadCore::new(config, Box::default(), &mut requests, &mut budget).unwrap();
    let id = core
        .put(
            &mut requests,
            SESSION,
            key(6),
            CacheVersion(0),
            0,
            1_000_000,
        )
        .unwrap();
    assert_eq!(sent(&mut core, &mut requests, 0), [Kind::PutBegin]);
    let foreign = reply(id, &requests, Kind::PutAuthority, |reply| {
        reply.key = key(7)
    });
    assert!(!core.receive(&mut requests, SESSION, &foreign, 10));
    assert_eq!(
        core.prepare(&mut requests, id, 0, 8192, TTL_MS),
        Err(PrepareRefused::Phase),
        "an AUTHORITY for another key binds nothing"
    );
    let authority = reply(id, &requests, Kind::PutAuthority, |_| {});
    assert!(core.receive(&mut requests, SESSION, &authority, 20));
    core.prepare(&mut requests, id, 0, 8192, TTL_MS).unwrap();
    assert_eq!(sent(&mut core, &mut requests, 30), [Kind::PutPrepare]);
    let foreign = reply(id, &requests, Kind::PutReady, |reply| reply.key = key(7));
    assert!(!core.receive(&mut requests, SESSION, &foreign, 40));
    assert_eq!(
        core.supply(&mut requests, id, 0, &[0; 8192]),
        Err(SupplyRefused::NotReady),
        "a READY for another key opens nothing"
    );
    let foreign = reply(id, &requests, Kind::PutResult, |reply| reply.key = key(7));
    assert!(!core.receive(&mut requests, SESSION, &foreign, 50));
    assert_eq!(core.outcome(&requests, id), None);
    let ready = reply(id, &requests, Kind::PutReady, |_| {});
    assert!(core.receive(&mut requests, SESSION, &ready, 60));
    assert_eq!(
        core.supply(&mut requests, id, 0, &[0; 8192]),
        Err(SupplyRefused::Slots),
        "the matching READY opens input, which this slotless core then refuses for space"
    );
}

/// After AUTHORITY binds a serial, a serial-0 refusal may answer an earlier BEGIN, so the bound attempt keeps waiting for its own terminal.
#[test]
fn a_serial_zero_refusal_after_authority_keeps_the_upload() {
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut budget = EngineBudget::new(1 << 20);
    let mut requests =
        ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let config = UploadConfig {
        retry_us: 1_000,
        attempts: 3,
    };
    let mut core = UploadCore::new(config, Box::default(), &mut requests, &mut budget).unwrap();
    let id = core
        .put(
            &mut requests,
            SESSION,
            key(6),
            CacheVersion(0),
            0,
            1_000_000,
        )
        .unwrap();
    assert_eq!(sent(&mut core, &mut requests, 0), [Kind::PutBegin]);
    let authority = reply(id, &requests, Kind::PutAuthority, |_| {});
    assert!(core.receive(&mut requests, SESSION, &authority, 10));
    core.prepare(&mut requests, id, 0, 0, TTL_MS).unwrap();
    assert_eq!(sent(&mut core, &mut requests, 20), [Kind::PutPrepare]);
    let stale = reply(id, &requests, Kind::PutError, |reply| {
        reply.allocation = 0;
        reply.status = Status::RequestPressure as u16;
    });
    assert!(!core.receive(&mut requests, SESSION, &stale, 30));
    assert_eq!(core.outcome(&requests, id), None, "the bound attempt stays");
    let forgotten = reply(id, &requests, Kind::PutError, |reply| {
        reply.allocation = 0;
        reply.status = Status::UnknownOutcome as u16;
    });
    assert!(core.receive(&mut requests, SESSION, &forgotten, 40));
    assert_eq!(core.outcome(&requests, id), Some(UploadOutcome::Unknown));
    assert!(!core.receive(&mut requests, SESSION, &stale, 50));
    let result = reply(id, &requests, Kind::PutResult, |_| {});
    assert!(core.receive(&mut requests, SESSION, &result, 60));
    assert_eq!(core.outcome(&requests, id), Some(UploadOutcome::Published));
}

/// `attempts` counts resends after the first send, as the fetch and bootstrap retries do: with one attempt a lost BEGIN is resent once, naming the same cache version as the first, and the upload ends `Unknown` at the retry after that.
#[test]
fn attempts_count_resends_after_the_first_send() {
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut budget = EngineBudget::new(1 << 20);
    let mut requests =
        ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let config = UploadConfig {
        retry_us: 1_000,
        attempts: 1,
    };
    let mut core = UploadCore::new(config, Box::default(), &mut requests, &mut budget).unwrap();
    let id = core
        .put(
            &mut requests,
            SESSION,
            key(6),
            CacheVersion(4),
            0,
            1_000_000,
        )
        .unwrap();
    let wire = requests.upload(id).unwrap().wire();
    let begins = |core: &mut UploadCore<'_>, requests: &mut ClientRequests<'_>, now_us| {
        let mut begins = Vec::new();
        core.poll(requests, now_us, 8, |_, header| {
            begins.push((header.kind, header.offset));
            true
        });
        begins
    };
    assert_eq!(begins(&mut core, &mut requests, 0), [(Kind::PutBegin, 4)]);
    core.handed(&mut requests, (PeerId(0), wire), true, true);
    core.tick(&mut requests, 1_000);
    assert_eq!(
        begins(&mut core, &mut requests, 1_000),
        [(Kind::PutBegin, 4)],
        "the one attempt resends the lost BEGIN at its version"
    );
    core.handed(&mut requests, (PeerId(0), wire), true, true);
    assert_eq!(core.outcome(&requests, id), None);
    core.tick(&mut requests, 2_000);
    assert!(sent(&mut core, &mut requests, 2_000).is_empty());
    assert_eq!(core.outcome(&requests, id), Some(UploadOutcome::Unknown));
}

/// What one turn of [`begin_turns`] showed: the upload's outcome right after the tick, the kinds of the frames the poll sent, and the outcome after the turn.
struct Turn {
    ticked: Option<UploadOutcome>,
    sent: Vec<Kind>,
    outcome: Option<UploadOutcome>,
}

/// Runs turns `0..=attempts + 2` of one upload whose client resends `attempts` times, one turn per retry interval: a tick, a poll whose send call takes every frame, then `handed` for a BEGIN that reached the send call. The upload's deadline lies far past the last turn, so only the resend limit can end it. `answer` runs after turn 0 and may deliver the owner's reply.
fn begin_turns(
    attempts: u32,
    answer: impl FnOnce(&mut UploadCore<'_>, &mut ClientRequests<'_>, RequestId),
) -> Vec<Turn> {
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut budget = EngineBudget::new(1 << 20);
    let mut requests =
        ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let config = UploadConfig {
        retry_us: 1_000,
        attempts,
    };
    let mut core = UploadCore::new(config, Box::default(), &mut requests, &mut budget).unwrap();
    let id = core
        .put(
            &mut requests,
            SESSION,
            key(6),
            CacheVersion(0),
            0,
            1_000_000,
        )
        .unwrap();
    let wire = requests.upload(id).unwrap().wire();
    let mut answer = Some(answer);
    let mut observed = Vec::new();
    for turn in 0..=u64::from(attempts) + 2 {
        let now = turn * 1_000;
        core.tick(&mut requests, now);
        let ticked = core.outcome(&requests, id);
        let sent = sent(&mut core, &mut requests, now);
        core.handed(&mut requests, (PeerId(0), wire), !sent.is_empty(), true);
        observed.push(Turn {
            ticked,
            sent,
            outcome: core.outcome(&requests, id),
        });
        if let Some(answer) = answer.take() {
            answer(&mut core, &mut requests, id);
        }
    }
    observed
}

/// Every BEGIN is lost, at a resend limit of 2 and of 3: turns 0 to `attempts` each send exactly one BEGIN and leave the upload undecided, the first send and each resend; no later turn sends a BEGIN; and the tick of the turn after the last resend decides the upload `Unknown`, and no turn before it.
#[test]
fn a_begin_lost_every_time_is_resent_to_the_limit_and_ends_unknown_a_turn_later() {
    for attempts in [2, 3] {
        let observed = begin_turns(attempts, |_, _, _| {});
        let per_turn: Vec<usize> = observed.iter().map(|turn| turn.sent.len()).collect();
        let outcomes: Vec<Option<UploadOutcome>> =
            observed.iter().map(|turn| turn.outcome).collect();
        let resending = attempts as usize + 1;
        assert!(
            (observed.iter().flat_map(|turn| &turn.sent)).all(|kind| *kind == Kind::PutBegin),
            "an upload with no authority sends only BEGINs"
        );
        assert_eq!(
            per_turn[..resending],
            vec![1; resending],
            "the first send and each of {attempts} resends, one a turn: {per_turn:?}"
        );
        assert_eq!(
            per_turn[resending..],
            [0, 0],
            "the turns after the last of {attempts} resends send no BEGIN"
        );
        assert_eq!(
            outcomes[..resending],
            vec![None; resending],
            "the upload is undecided through the last of its {attempts} resends"
        );
        assert_eq!(
            observed[resending].ticked,
            Some(UploadOutcome::Unknown),
            "the tick after the last of {attempts} resends decides the upload"
        );
        assert_eq!(
            outcomes[resending..],
            [Some(UploadOutcome::Unknown); 2],
            "the upload stays Unknown after {attempts} resends"
        );
    }
}

/// The owner's AUTHORITY arrives after turn 0, so the upload stays undecided on every turn while it waits for its PREPARE.
#[test]
fn an_answered_begin_is_not_resent_and_the_upload_stays_undecided() {
    let observed = begin_turns(3, |core, requests, id| {
        let upload = requests.upload(id).unwrap();
        let authority = Header {
            allocation: 5,
            ..header(Kind::PutAuthority, upload.wire(), upload.key())
        };
        assert!(
            core.receive(requests, SESSION, &authority, 500),
            "the client accepts the owner's AUTHORITY"
        );
    });
    let per_turn: Vec<usize> = observed.iter().map(|turn| turn.sent.len()).collect();
    let outcomes: Vec<Option<UploadOutcome>> = observed.iter().map(|turn| turn.outcome).collect();
    let mut expected = vec![0; observed.len()];
    expected[0] = 1;
    assert_eq!(observed[0].sent, [Kind::PutBegin]);
    assert_eq!(per_turn, expected, "an answered BEGIN is sent once");
    assert_eq!(outcomes, vec![None; observed.len()]);
}

/// Each poll's scan starts after the slot the last one reached, so with one send per poll two due uploads alternate instead of the lower slot retrying ahead of the other's first send.
#[test]
fn one_send_per_poll_rotates_across_due_uploads() {
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut budget = EngineBudget::new(1 << 20);
    let mut requests =
        ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let config = UploadConfig {
        retry_us: 1_000,
        attempts: 3,
    };
    let mut core = UploadCore::new(config, Box::default(), &mut requests, &mut budget).unwrap();
    let ids: Vec<RequestId> = (0..2)
        .map(|_| {
            core.put(
                &mut requests,
                SESSION,
                key(6),
                CacheVersion(0),
                0,
                1_000_000,
            )
            .unwrap()
        })
        .collect();
    let wires: Vec<u64> = ids
        .iter()
        .map(|&id| requests.upload(id).unwrap().wire())
        .collect();
    let mut order = Vec::new();
    for turn in 0..4u64 {
        let now = turn * 1_000;
        core.tick(&mut requests, now);
        let mut staged = Vec::new();
        core.poll(&mut requests, now, 1, |_, header| {
            staged.push(header.request);
            true
        });
        for &wire in &staged {
            core.handed(&mut requests, (PeerId(0), wire), true, true);
        }
        order.extend(staged);
    }
    assert_eq!(
        order,
        [wires[0], wires[1], wires[0], wires[1]],
        "each upload gets every other send"
    );
}

#[test]
fn every_live_upload_retries_after_one_between_them_retires() {
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut budget = EngineBudget::new(1 << 20);
    let mut requests =
        ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let config = UploadConfig {
        retry_us: 1_000,
        attempts: 3,
    };
    let mut core = UploadCore::new(config, Box::default(), &mut requests, &mut budget).unwrap();
    let ids: Vec<RequestId> = (0..3)
        .map(|_| {
            core.put(
                &mut requests,
                SESSION,
                key(6),
                CacheVersion(0),
                0,
                1_000_000,
            )
            .unwrap()
        })
        .collect();
    assert_eq!(sent(&mut core, &mut requests, 0), [Kind::PutBegin; 3]);
    let refused = reply(ids[1], &requests, Kind::PutError, |reply| {
        reply.status = Status::PermissionDenied as u16
    });
    assert!(core.receive(&mut requests, SESSION, &refused, 10));
    assert!(
        !core.close(&mut requests, ids[0]),
        "an undecided upload stays"
    );
    assert!(core.close(&mut requests, ids[1]));
    let reused = core
        .put(
            &mut requests,
            SESSION,
            key(7),
            CacheVersion(0),
            20,
            1_000_000,
        )
        .unwrap();
    assert_eq!(reused.slot(), ids[1].slot());
    assert_eq!(sent(&mut core, &mut requests, 20), [Kind::PutBegin]);
    core.tick(&mut requests, 1_000);
    assert_eq!(sent(&mut core, &mut requests, 1_000), [Kind::PutBegin; 2]);
    core.tick(&mut requests, 1_020);
    assert_eq!(sent(&mut core, &mut requests, 1_020), [Kind::PutBegin]);
    assert_eq!(core.wake(&requests), (false, Some(2_000)));
    let before = crate::instrument::allocations();
    let mut last = reused;
    for round in 0..8 {
        let refused = reply(last, &requests, Kind::PutError, |reply| {
            reply.status = Status::PermissionDenied as u16
        });
        assert!(core.receive(&mut requests, SESSION, &refused, 1_100));
        assert!(core.close(&mut requests, last), "round {round}");
        last = core
            .put(
                &mut requests,
                SESSION,
                key(7),
                CacheVersion(0),
                1_100,
                1_000_000,
            )
            .unwrap();
    }
    assert_eq!(
        crate::instrument::allocations() - before,
        0,
        "retiring and readmitting reuses the index"
    );
}

#[test]
fn a_device_held_piece_below_the_receipt_keeps_its_slot() {
    let shared = arena(2);
    let mut budget = EngineBudget::new(1 << 20);
    let slots = sources(&shared, 2, &mut budget).unwrap();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut requests =
        ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let config = UploadConfig {
        retry_us: 1_000,
        attempts: 3,
    };
    let mut core = UploadCore::new(config, slots, &mut requests, &mut budget).unwrap();
    let object = payload(3 * 8192, 33);
    let id = core
        .put(
            &mut requests,
            SESSION,
            key(6),
            CacheVersion(0),
            0,
            1_000_000,
        )
        .unwrap();
    assert_eq!(sent(&mut core, &mut requests, 0), [Kind::PutBegin]);
    let authority = reply(id, &requests, Kind::PutAuthority, |_| {});
    assert!(core.receive(&mut requests, SESSION, &authority, 10));
    core.prepare(&mut requests, id, 0, 3 * 8192, TTL_MS)
        .unwrap();
    assert_eq!(sent(&mut core, &mut requests, 20), [Kind::PutPrepare]);
    let ready = reply(id, &requests, Kind::PutReady, |reply| reply.grant = 3);
    assert!(core.receive(&mut requests, SESSION, &ready, 30));
    assert_eq!(core.supply(&mut requests, id, 0, &object[..8192]), Ok(8192));
    assert_eq!(
        core.supply(&mut requests, id, 1, &object[8192..16384]),
        Ok(8192)
    );
    let hold = core.slots()[0].piece().unwrap().hold().unwrap();
    let ack = reply(id, &requests, Kind::PutAck, |reply| {
        reply.index = 2;
        reply.grant = 3;
    });
    assert!(core.receive(&mut requests, SESSION, &ack, 40));
    assert_eq!(
        core.supply(&mut requests, id, 2, &object[16384..]),
        Ok(8192)
    );
    let pieces: Vec<_> = core
        .slots()
        .iter()
        .map(|slot| slot.piece().map(|piece| piece.bytes().to_vec()))
        .collect();
    assert_eq!(
        pieces,
        [
            Some(object[..8192].to_vec()),
            Some(object[16384..].to_vec())
        ],
        "the device-held piece keeps its slot and bytes"
    );
    drop(hold);
    core.tick(&mut requests, 50);
    assert!(core.slots()[0].piece().is_none());
}

fn kind_of(bytes: &[u8]) -> Option<Kind> {
    parse(Crc32c::detect(), bytes, false)
        .ok()
        .map(|frame| frame.header().kind)
}

#[test]
fn a_lost_zero_byte_result_resolves_on_the_prepare_retry() {
    scene(&PRINCIPALS, |mut scene| {
        let now = scene.turn * 100;
        let id = scene.clients[0]
            .put(key(6), CacheVersion(0), now, 30_000_000)
            .unwrap();
        drive(&mut scene, 4);
        scene.clients[0].prepare(id, 0, 0, TTL_MS).unwrap();
        let mut results = 0;
        // The first RESULT leaves the link toward the client right after
        // the owner's poll that sends it, before the client can take it.
        for _ in 0..400 {
            drive_then(&mut scene, 1, &mut |_, nets| {
                nets[0].borrow_mut().retain(0, |bytes| {
                    let result = kind_of(bytes) == Some(Kind::PutResult);
                    results += usize::from(result);
                    !(result && results == 1)
                });
            });
            if scene.clients[0].put_outcome(id).is_some() {
                break;
            }
        }
        assert!(
            results >= 2,
            "the first RESULT dropped and a retry replayed it"
        );
        assert_eq!(
            scene.clients[0].put_outcome(id),
            Some(UploadOutcome::Published)
        );
    });
}

/// A RESULT held on the wire past the client's deadline: the upload decides
/// Unknown and the delayed RESULT resolves it to Published, after an abandon
/// as well, since abandon ends only the wait; once the upload is retired, a
/// successor PUT of the same key on the same wire slot, driven to READY, stays
/// undecided by a replayed RESULT of the retired request and decides only by
/// its own.
#[test]
fn a_delayed_result_resolves_a_retained_unknown_and_is_inert_after_retire() {
    for abandon_first in [false, true] {
        scene(&PRINCIPALS, |mut scene| {
            let object = payload(8192, 47);
            let id = upload(&mut scene, 6, &object, 20_000);
            assert!(scene.clients[0].supply(id, 0, &object).is_ok());
            // Every ACK and RESULT toward the client is held back on the wire.
            let mut held: Vec<Vec<u8>> = Vec::new();
            let mut acks: Vec<Vec<u8>> = Vec::new();
            // Each turn's owner action holds them right after its poll sends
            // them, before the client can take them.
            let hold_results = |nets: &[Rc<RefCell<Net<'_>>>; 2],
                                held: &mut Vec<Vec<u8>>,
                                acks: &mut Vec<Vec<u8>>| {
                nets[0]
                    .borrow_mut()
                    .retain(0, |bytes| match kind_of(bytes) {
                        Some(Kind::PutResult) => {
                            held.push(bytes.to_vec());
                            false
                        }
                        Some(Kind::PutAck) => {
                            acks.push(bytes.to_vec());
                            false
                        }
                        _ => true,
                    });
            };
            for _ in 0..400 {
                drive_then(&mut scene, 1, &mut |_, nets| {
                    hold_results(nets, &mut held, &mut acks);
                });
                if scene.clients[0].put_outcome(id).is_some() {
                    break;
                }
            }
            assert!(
                held.len() >= 2,
                "the owner published and answered each PREPARE retry with a RESULT, all held"
            );
            assert!(!acks.is_empty(), "the owner acknowledged the DATA");
            assert_eq!(
                scene.clients[0].put_outcome(id),
                Some(UploadOutcome::Unknown),
                "the deadline passed with every RESULT held"
            );
            if abandon_first {
                assert!(scene.clients[0].abandon(id));
            }
            scene.nets[0].borrow_mut().inject(0, &held[0]);
            drive(&mut scene, 4);
            assert_eq!(
                scene.clients[0].put_outcome(id),
                Some(UploadOutcome::Published),
                "a matching RESULT resolves the retained Unknown"
            );
            assert!(scene.clients[0].retire(id));
            // The successor names the same key on the same wire slot under the
            // next generation, with its own RESULT held back.
            let next = upload(&mut scene, 6, &object, 20_000);
            assert_eq!(next.slot(), id.slot(), "the successor reuses the wire slot");
            assert!(scene.clients[0].supply(next, 0, &object).is_ok());
            let mut later: Vec<Vec<u8>> = Vec::new();
            let mut later_acks: Vec<Vec<u8>> = Vec::new();
            for _ in 0..40 {
                drive_then(&mut scene, 1, &mut |_, nets| {
                    hold_results(nets, &mut later, &mut later_acks);
                });
            }
            assert!(!later.is_empty(), "the successor's own RESULT was held");
            assert_eq!(scene.clients[0].put_outcome(next), None);
            let receipt = scene.clients[0].put_receipt(next);
            assert_eq!(receipt.map(|(_, base, _)| base), Some(0));
            // An ACK and a RESULT of the retired request, which the session
            // admits as fresh sequences.
            let session = scene.clients[0].sessions_mut().report();
            scene.nets[0].borrow_mut().inject(0, &acks[0]);
            scene.nets[0].borrow_mut().inject(0, &held[1]);
            drive(&mut scene, 4);
            let after = scene.clients[0].sessions_mut().report();
            assert_eq!(
                (after.stale, after.duplicate),
                (session.stale, session.duplicate),
                "the session admitted the retired request's unseen ACK and RESULT"
            );
            assert_eq!(
                scene.clients[0].put_outcome(next),
                None,
                "the retired request's RESULT reaches no successor"
            );
            assert_eq!(
                scene.clients[0].put_receipt(next),
                receipt,
                "the retired request's ACK moves no successor receipt"
            );
            scene.nets[0].borrow_mut().inject(0, &later[0]);
            drive(&mut scene, 4);
            assert_eq!(
                scene.clients[0].put_outcome(next),
                Some(UploadOutcome::Published)
            );
            assert_eq!(scene.fetch(6), object);
        });
    }
}

/// A reply that crosses a PUT CANCEL on the wire makes the CANCEL due again, and the next poll resends it, so a lost CANCEL or a lost refusal still ends the upload `Failed(Cancelled)`.
#[test]
fn a_reply_crossing_a_cancel_makes_the_cancel_due_again() {
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut budget = EngineBudget::new(1 << 20);
    let mut requests =
        ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let config = UploadConfig {
        retry_us: 1_000,
        attempts: 3,
    };
    let mut core = UploadCore::new(config, Box::default(), &mut requests, &mut budget).unwrap();
    let id = core
        .put(
            &mut requests,
            SESSION,
            key(6),
            CacheVersion(0),
            0,
            1_000_000,
        )
        .unwrap();
    let wire = requests.upload(id).unwrap().wire();
    assert_eq!(sent(&mut core, &mut requests, 0), [Kind::PutBegin]);
    core.handed(&mut requests, (PeerId(0), wire), true, true);
    core.cancel(&mut requests, id);
    assert_eq!(sent(&mut core, &mut requests, 10), [Kind::PutCancel]);
    let authority = reply(id, &requests, Kind::PutAuthority, |_| {});
    assert!(core.receive(&mut requests, SESSION, &authority, 20));
    assert!(
        core.wake(&requests).0,
        "the crossing AUTHORITY makes the CANCEL due"
    );
    assert_eq!(
        sent(&mut core, &mut requests, 30),
        [Kind::PutCancel],
        "the CANCEL is resent"
    );
    let cancelled = reply(id, &requests, Kind::PutError, |reply| {
        reply.status = Status::Cancelled as u16
    });
    assert!(core.receive(&mut requests, SESSION, &cancelled, 40));
    assert_eq!(
        core.outcome(&requests, id),
        Some(UploadOutcome::Failed(Status::Cancelled))
    );
}

#[test]
fn a_begin_in_a_refused_send_call_is_unknown() {
    scene(&PRINCIPALS, |mut scene| {
        let now = scene.turn * 100;
        let blocked = Faults {
            would_block: 100,
            ..Faults::default()
        };
        scene.nets[0].borrow_mut().set_faults(1, blocked);
        let id = scene.clients[0]
            .put(key(6), CacheVersion(0), now, 1_000)
            .unwrap();
        scene.clients[0].poll(now);
        scene.clients[0].poll(now + 1_000);
        assert_eq!(
            scene.clients[0].put_outcome(id),
            Some(UploadOutcome::Unknown)
        );
    });
}

pub(super) fn ready_core<'a>(
    slots: Box<[super::upload::SourceSlot<'a>]>,
    requests: &mut ClientRequests<'a>,
    budget: &mut EngineBudget,
    total: u32,
) -> (UploadCore<'a>, RequestId) {
    let config = UploadConfig {
        retry_us: 1_000,
        attempts: 3,
    };
    let mut core = UploadCore::new(config, slots, requests, budget).unwrap();
    let id = core
        .put(requests, SESSION, key(6), CacheVersion(0), 0, 1_000_000)
        .unwrap();
    assert_eq!(sent(&mut core, requests, 0), [Kind::PutBegin]);
    let authority = reply(id, requests, Kind::PutAuthority, |_| {});
    assert!(core.receive(requests, SESSION, &authority, 10));
    core.prepare(requests, id, 0, total, TTL_MS).unwrap();
    assert_eq!(sent(&mut core, requests, 20), [Kind::PutPrepare]);
    let ready = reply(id, requests, Kind::PutReady, |reply| reply.grant = 64);
    assert!(core.receive(requests, SESSION, &ready, 30));
    (core, id)
}

fn pieces(core: &UploadCore<'_>) -> Vec<Vec<u8>> {
    let mut held: Vec<Vec<u8>> = core
        .slots()
        .iter()
        .filter_map(|slot| slot.piece())
        .map(|piece| piece.bytes().to_vec())
        .collect();
    held.sort();
    held
}

/// With one source slot free, a slot a device still reads below the receipt base stays at the head of the upload's chain and leaves the wanted index where the held run from the base ends: three slots hold fragments 0 and 1, a device reads fragment 1's, and a receipt of both frees fragment 0's slot and parks fragment 1's. Fragment 2 takes one of the two free slots, an out-of-order fragment 4 is refused naming 3, and fragment 3 takes the last slot.
#[test]
fn a_parked_slot_below_the_base_leaves_the_wanted_index_at_the_held_run() {
    let shared = arena(3);
    let mut budget = EngineBudget::new(1 << 20);
    let slots = sources(&shared, 3, &mut budget).unwrap();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut requests =
        ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let (mut core, id) = ready_core(slots, &mut requests, &mut budget, 5 * 8192);
    let object = payload(5 * 8192, 35);
    let piece = |index: usize| &object[index * 8192..(index + 1) * 8192];
    assert_eq!(core.supply(&mut requests, id, 0, piece(0)), Ok(8192));
    assert_eq!(core.supply(&mut requests, id, 1, piece(1)), Ok(8192));
    let reading = core
        .slots()
        .iter()
        .find_map(|slot| slot.piece().filter(|held| held.bytes() == piece(1)))
        .unwrap();
    let hold = reading.hold().unwrap();
    let ack = reply(id, &requests, Kind::PutAck, |reply| {
        reply.index = 2;
        reply.grant = 64;
    });
    assert!(core.receive(&mut requests, SESSION, &ack, 40));
    assert_eq!(
        listed(&core),
        2,
        "fragment 0's slot freed, fragment 1's parked"
    );
    assert_eq!(core.supply(&mut requests, id, 2, piece(2)), Ok(8192));
    let before = core.snapshot(&requests, id);
    assert_eq!(
        core.supply(&mut requests, id, 4, piece(4)),
        Err(SupplyRefused::Prefix(3))
    );
    assert_eq!(
        core.snapshot(&requests, id),
        before,
        "the refusal changes nothing"
    );
    assert_eq!(core.supply(&mut requests, id, 3, piece(3)), Ok(8192));
    drop(hold);
}

/// With one source slot free, `SupplyRefused::Prefix` names the first missing fragment at or above the receipt base. Every refusal preserves the upload's state.
#[test]
fn the_last_slot_names_the_index_after_the_held_run_or_its_first_gap() {
    let shared = arena(5);
    let mut budget = EngineBudget::new(1 << 20);
    let slots = sources(&shared, 5, &mut budget).unwrap();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut requests =
        ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let (mut core, id) = ready_core(slots, &mut requests, &mut budget, 10 * 8192);
    let object = payload(10 * 8192, 36);
    let piece = |index: u32| &object[index as usize * 8192..(index as usize + 1) * 8192];
    for index in [0, 1, 2, 7] {
        assert_eq!(
            core.supply(&mut requests, id, index, piece(index)),
            Ok(8192)
        );
    }
    let refused = |core: &mut UploadCore<'_>, requests: &mut ClientRequests<'_>, index, wanted| {
        let before = core.snapshot(requests, id);
        assert_eq!(
            core.supply(requests, id, index, piece(index)),
            Err(SupplyRefused::Prefix(wanted)),
            "fragment {index}"
        );
        assert_eq!(core.snapshot(requests, id), before, "fragment {index}");
    };
    let receipt = |requests: &ClientRequests<'_>, base| {
        reply(id, requests, Kind::PutAck, |reply| {
            reply.index = base;
            reply.grant = 64;
        })
    };
    refused(&mut core, &mut requests, 5, 3);
    assert_eq!(core.supply(&mut requests, id, 3, piece(3)), Ok(8192));
    let ack = receipt(&requests, 1);
    assert!(core.receive(&mut requests, SESSION, &ack, 40));
    refused(&mut core, &mut requests, 6, 4);
    assert_eq!(core.supply(&mut requests, id, 4, piece(4)), Ok(8192));
    let ack = receipt(&requests, 3);
    assert!(core.receive(&mut requests, SESSION, &ack, 50));
    assert_eq!(core.supply(&mut requests, id, 6, piece(6)), Ok(8192));
    refused(&mut core, &mut requests, 9, 5);
    assert_eq!(core.supply(&mut requests, id, 5, piece(5)), Ok(8192));
}

#[test]
fn out_of_order_pieces_are_held_once_and_freed_by_their_receipt() {
    let shared = arena(4);
    let mut budget = EngineBudget::new(1 << 20);
    let slots = sources(&shared, 4, &mut budget).unwrap();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut requests =
        ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let (mut core, id) = ready_core(slots, &mut requests, &mut budget, 5 * 8192);
    let object = payload(5 * 8192, 34);
    let piece = |index: usize| &object[index * 8192..(index + 1) * 8192];
    assert_eq!(core.supply(&mut requests, id, 2, piece(2)), Ok(8192));
    assert_eq!(core.supply(&mut requests, id, 0, piece(0)), Ok(8192));
    assert_eq!(
        core.supply(&mut requests, id, 2, piece(2)),
        Err(SupplyRefused::Index)
    );
    assert_eq!(
        core.supply(&mut requests, id, 0, piece(0)),
        Err(SupplyRefused::Index)
    );
    assert_eq!(core.supply(&mut requests, id, 1, piece(1)), Ok(8192));
    assert_eq!(core.supply(&mut requests, id, 3, piece(3)), Ok(8192));
    assert_eq!(
        core.supply(&mut requests, id, 4, piece(4)),
        Err(SupplyRefused::Slots),
        "every slot holds an unreceipted piece"
    );
    assert_eq!(
        core.supply(&mut requests, id, 1, piece(1)),
        Err(SupplyRefused::Index),
        "a held repeat is refused before the slot shortage"
    );
    let ack = reply(id, &requests, Kind::PutAck, |reply| {
        reply.index = 2;
        reply.grant = 64;
    });
    assert!(core.receive(&mut requests, SESSION, &ack, 40));
    assert_eq!(core.supply(&mut requests, id, 4, piece(4)), Ok(8192));
    assert_eq!(
        core.supply(&mut requests, id, 1, piece(1)),
        Err(SupplyRefused::Index),
        "a receipted index stays refused"
    );
    let mut expected = vec![piece(2).to_vec(), piece(3).to_vec(), piece(4).to_vec()];
    expected.sort();
    assert_eq!(pieces(&core), expected);
}

#[test]
fn an_ack_arms_the_wake_before_the_next_tick() {
    let shared = arena(2);
    let mut budget = EngineBudget::new(1 << 20);
    let slots = sources(&shared, 2, &mut budget).unwrap();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut requests =
        ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let (mut core, id) = ready_core(slots, &mut requests, &mut budget, 8192);
    let object = payload(8192, 35);
    core.tick(&mut requests, 100);
    assert_eq!(
        core.wake(&requests),
        (false, Some(1_030)),
        "READY arms the retry that asks a stalled grant for a fresh READY"
    );
    assert_eq!(core.supply(&mut requests, id, 0, &object), Ok(8192));
    let full = reply(id, &requests, Kind::PutAck, |reply| {
        reply.index = 1;
        reply.grant = 64;
    });
    assert!(core.receive(&mut requests, SESSION, &full, 200));
    assert_eq!(
        core.wake(&requests),
        (false, Some(1_200)),
        "the full receipt arms the PREPARE retry"
    );
    assert_eq!(pieces(&core), Vec::<Vec<u8>>::new());
    core.tick(&mut requests, 1_150);
    assert!(sent(&mut core, &mut requests, 1_150).is_empty());
    core.tick(&mut requests, 1_200);
    assert_eq!(sent(&mut core, &mut requests, 1_200), [Kind::PutPrepare]);
}

/// A DATA send the session refuses ends the upload; the fragments the same turn staged before it keep their slots until the next tick, so the staged frames still read their bytes when the transport takes them.
#[test]
fn a_refused_data_send_keeps_the_staged_prefix_held() {
    let shared = arena(4);
    let mut budget = EngineBudget::new(1 << 20);
    let slots = sources(&shared, 4, &mut budget).unwrap();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut requests =
        ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let (mut core, id) = ready_core(slots, &mut requests, &mut budget, 2 * 8192);
    let object = payload(2 * 8192, 51);
    assert_eq!(core.supply(&mut requests, id, 0, &object[..8192]), Ok(8192));
    assert_eq!(core.supply(&mut requests, id, 1, &object[8192..]), Ok(8192));
    let mut staged = Vec::new();
    let sent = core.data(&mut requests, 2, |_, header, slot, _| {
        staged.push((header.index, slot));
        staged.len() == 1
    });
    assert_eq!((sent, staged.len()), (1, 2));
    assert_eq!(core.outcome(&requests, id), Some(UploadOutcome::Unknown));
    let first = usize::from(staged[0].1);
    assert_eq!(
        core.slots()[first]
            .piece()
            .map(|piece| piece.bytes().to_vec()),
        Some(object[..8192].to_vec()),
        "the staged fragment keeps its slot through the send"
    );
    core.tick(&mut requests, 100);
    assert_eq!(pieces(&core), Vec::<Vec<u8>>::new());
}

#[test]
fn a_decided_upload_returns_its_pieces_at_the_decision() {
    let shared = arena(2);
    let mut budget = EngineBudget::new(1 << 20);
    let slots = sources(&shared, 2, &mut budget).unwrap();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut requests =
        ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let (mut core, id) = ready_core(slots, &mut requests, &mut budget, 2 * 8192);
    let object = payload(2 * 8192, 36);
    assert_eq!(core.supply(&mut requests, id, 0, &object[..8192]), Ok(8192));
    let refused = reply(id, &requests, Kind::PutError, |reply| {
        reply.status = Status::TimedOut as u16
    });
    assert!(core.receive(&mut requests, SESSION, &refused, 50));
    assert_eq!(
        core.outcome(&requests, id),
        Some(UploadOutcome::Failed(Status::TimedOut))
    );
    assert_eq!(
        pieces(&core).len(),
        0,
        "the decision frees a piece no device reads"
    );
    let other = core
        .put(
            &mut requests,
            SESSION,
            key(7),
            CacheVersion(0),
            60,
            1_000_000,
        )
        .unwrap();
    assert_eq!(sent(&mut core, &mut requests, 60), [Kind::PutBegin]);
    let authority = reply(other, &requests, Kind::PutAuthority, |_| {});
    assert!(core.receive(&mut requests, SESSION, &authority, 70));
    core.prepare(&mut requests, other, 0, 2 * 8192, TTL_MS)
        .unwrap();
    assert_eq!(sent(&mut core, &mut requests, 80), [Kind::PutPrepare]);
    let ready = reply(other, &requests, Kind::PutReady, |reply| reply.grant = 64);
    assert!(core.receive(&mut requests, SESSION, &ready, 90));
    assert_eq!(
        core.supply(&mut requests, other, 0, &object[..8192]),
        Ok(8192)
    );
    assert_eq!(
        core.supply(&mut requests, other, 1, &object[8192..]),
        Ok(8192),
        "the decided upload's slot serves the next upload"
    );
    assert_eq!(pieces(&core).len(), 2);
    assert!(core.close(&mut requests, id));
    assert_eq!(pieces(&core).len(), 2, "the live upload's pieces stay");
}

#[test]
fn retiring_an_upload_between_others_keeps_their_timers() {
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut budget = EngineBudget::new(1 << 20);
    let mut requests =
        ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let config = UploadConfig {
        retry_us: 1_000,
        attempts: 3,
    };
    let mut core = UploadCore::new(config, Box::default(), &mut requests, &mut budget).unwrap();
    let ids: Vec<RequestId> = (0..4)
        .map(|at| {
            core.put(
                &mut requests,
                SESSION,
                key(6),
                CacheVersion(0),
                at * 10,
                5_000,
            )
            .unwrap()
        })
        .collect();
    assert_eq!(sent(&mut core, &mut requests, 30), [Kind::PutBegin; 4]);
    for &id in &ids[..2] {
        let refused = reply(id, &requests, Kind::PutError, |reply| {
            reply.status = Status::PermissionDenied as u16
        });
        assert!(core.receive(&mut requests, SESSION, &refused, 40));
        assert!(core.close(&mut requests, id));
    }
    core.tick(&mut requests, 1_030);
    assert_eq!(
        sent(&mut core, &mut requests, 1_030),
        [Kind::PutBegin; 2],
        "both remaining uploads retry"
    );
    assert_eq!(core.wake(&requests), (false, Some(2_030)));
    core.tick(&mut requests, 5_020);
    assert_eq!(
        core.outcome(&requests, ids[2]),
        Some(UploadOutcome::NotStarted),
        "no BEGIN was handed to a send call"
    );
    assert_eq!(
        core.outcome(&requests, ids[3]),
        None,
        "its deadline is 5_030"
    );
    core.tick(&mut requests, 5_030);
    assert_eq!(
        core.outcome(&requests, ids[3]),
        Some(UploadOutcome::NotStarted)
    );
    assert!(
        core.close(&mut requests, ids[3]),
        "the upload moved to the front retires"
    );
    assert!(core.close(&mut requests, ids[2]));
    assert_eq!(core.wake(&requests), (false, None));
    let last = core
        .put(
            &mut requests,
            SESSION,
            key(8),
            CacheVersion(0),
            6_000,
            1_000,
        )
        .unwrap();
    assert_eq!(sent(&mut core, &mut requests, 6_000), [Kind::PutBegin]);
    core.tick(&mut requests, 6_000);
    assert_eq!(core.wake(&requests), (false, Some(7_000)));
    core.tick(&mut requests, 7_000);
    assert_eq!(
        core.outcome(&requests, last),
        Some(UploadOutcome::NotStarted)
    );
}

struct Modeled {
    id: RequestId,
    tag: u8,
    count: u32,
    total: usize,
    base: u32,
    received: bool,
    decided: bool,
    supplied: Vec<u32>,
}

impl Modeled {
    fn len(&self, index: u32) -> usize {
        (self.total - index as usize * 8192).min(8192)
    }

    fn live(&self, index: u32) -> bool {
        !self.decided && index >= self.base && self.supplied.contains(&index)
    }

    /// The lowest index at or above the receipt base the upload holds no slot for.
    fn wanted(&self) -> u32 {
        (self.base..).find(|&at| !self.live(at)).unwrap()
    }
}

/// The slots on the free list: every slot that holds no fragment.
fn listed(core: &UploadCore<'_>) -> usize {
    core.slots()
        .iter()
        .filter(|slot| slot.piece().is_none())
        .count()
}

/// The slots a supply can take: those on the free list, or, when it is empty, the `reclaimable` slots a supply's reclaim frees first.
fn free_slots(core: &UploadCore<'_>, reclaimable: usize) -> usize {
    match listed(core) {
        0 => reclaimable,
        free => free,
    }
}

/// The number of live fragments the modeled uploads hold.
fn live_total(uploads: &[Modeled]) -> usize {
    uploads
        .iter()
        .map(|upload| {
            upload
                .supplied
                .iter()
                .filter(|&&at| upload.live(at))
                .count()
        })
        .sum()
}

fn tagged(tag: u8, index: u32, len: usize) -> Vec<u8> {
    let mut bytes = vec![tag.wrapping_mul(7) ^ index as u8; len];
    bytes[0] = tag;
    bytes[1..5].copy_from_slice(&index.to_le_bytes());
    bytes
}

fn named(bytes: &[u8]) -> (u8, u32) {
    (
        bytes[0],
        u32::from_le_bytes(bytes[1..5].try_into().unwrap()),
    )
}

#[test]
fn source_slots_keep_every_live_fragment_under_random_schedules() {
    const SLOTS: usize = 5;
    // States where every slot holds a live fragment and the last slot's taker is undecided, the states the progress check reads.
    let mut full_states = 0;
    for seed in 1..=300u64 {
        let shared = arena(SLOTS as u32);
        let mut budget = EngineBudget::new(1 << 20);
        let slots = sources(&shared, SLOTS as u32, &mut budget).unwrap();
        let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
        let mut requests =
            ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
        let config = UploadConfig {
            retry_us: u64::MAX / 4,
            attempts: 3,
        };
        let mut core = UploadCore::new(config, slots, &mut requests, &mut budget).unwrap();
        let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let mut next = |bound: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % bound
        };
        let mut uploads: Vec<Modeled> = Vec::new();
        let mut holds = Vec::new();
        let mut tags = 0u8;
        // The upload whose supply took the last free slot.
        let mut last = None;
        for step in 0..400u64 {
            let at = |uploads: &Vec<Modeled>, pick: u64| pick as usize % uploads.len().max(1);
            match next(8) {
                0 if uploads.len() < 3 => {
                    tags = tags.wrapping_add(1);
                    let count = 1 + next(9) as u32;
                    let total = (count as usize - 1) * 8192 + 5 + next(8188) as usize;
                    let id = core
                        .put(
                            &mut requests,
                            SESSION,
                            key(6),
                            CacheVersion(0),
                            step,
                            u64::MAX / 4,
                        )
                        .unwrap();
                    let _ = sent(&mut core, &mut requests, step);
                    let authority = reply(id, &requests, Kind::PutAuthority, |_| {});
                    assert!(core.receive(&mut requests, SESSION, &authority, step));
                    core.prepare(&mut requests, id, 0, total as u32, TTL_MS)
                        .unwrap();
                    let _ = sent(&mut core, &mut requests, step);
                    let ready = reply(id, &requests, Kind::PutReady, |reply| reply.grant = 9);
                    assert!(core.receive(&mut requests, SESSION, &ready, step));
                    uploads.push(Modeled {
                        id,
                        tag: tags,
                        count,
                        total,
                        base: 0,
                        received: false,
                        decided: false,
                        supplied: Vec::new(),
                    });
                }
                0..=2 if !uploads.is_empty() => {
                    let pick = at(&uploads, next(8));
                    let upload = &uploads[pick];
                    let index = (u64::from(upload.base) + next(4)).saturating_sub(1) as u32;
                    let exact = next(8) != 0;
                    let len = if index < upload.count {
                        upload.len(index)
                    } else {
                        8192
                    };
                    let bytes = tagged(upload.tag, index, if exact { len } else { len - 1 });
                    let live = live_total(&uploads);
                    let mut parked: Vec<(u8, u32)> = holds
                        .iter()
                        .map(|(_, tag, index, _)| (*tag, *index))
                        .filter(|&(tag, index)| {
                            uploads
                                .iter()
                                .all(|upload| upload.tag != tag || !upload.live(index))
                        })
                        .collect();
                    parked.sort_unstable();
                    parked.dedup();
                    let parked = parked.len();
                    let expected = if upload.decided || upload.received {
                        Err(SupplyRefused::NotReady)
                    } else if index < upload.base
                        || index >= upload.count
                        || upload.supplied.contains(&index)
                    {
                        Err(SupplyRefused::Index)
                    } else if !exact {
                        Err(SupplyRefused::Length)
                    } else if live + parked >= SLOTS {
                        Err(SupplyRefused::Slots)
                    } else if free_slots(&core, SLOTS - live - parked) == 1
                        && index != upload.wanted()
                    {
                        Err(SupplyRefused::Prefix(upload.wanted()))
                    } else {
                        Ok(len)
                    };
                    let before = core.snapshot(&requests, upload.id);
                    // A supply that finds the free list empty first reclaims returned slots, which a refusal keeps.
                    let listed = listed(&core) > 0;
                    let got = core.supply(&mut requests, upload.id, index, &bytes);
                    assert_eq!(got, expected, "seed {seed} step {step}");
                    if listed && matches!(got, Err(SupplyRefused::Prefix(_))) {
                        assert_eq!(
                            core.snapshot(&requests, upload.id),
                            before,
                            "a prefix refusal changes nothing, seed {seed} step {step}"
                        );
                    }
                    if got.is_ok() {
                        let upload = &mut uploads[pick];
                        let base = upload.base;
                        upload.supplied.retain(|&at| at >= base);
                        upload.supplied.push(index);
                        if live + parked + 1 == SLOTS {
                            last = Some(upload.tag);
                        }
                    }
                }
                3 if !uploads.is_empty() => {
                    let pick = at(&uploads, next(8));
                    let upload = &mut uploads[pick];
                    let index = upload.base + next(3) as u32;
                    let ack = reply(upload.id, &requests, Kind::PutAck, |reply| {
                        reply.index = index;
                        reply.grant = index + 9;
                    });
                    let accepted = core.receive(&mut requests, SESSION, &ack, step);
                    // A full receipt keeps taking ACKs: each one proves the owner live while the RESULT is awaited.
                    assert_eq!(accepted, !upload.decided);
                    if accepted {
                        upload.base = upload.base.max(index);
                        upload.received = upload.base >= upload.count;
                    }
                }
                4 if !uploads.is_empty() && next(3) == 0 => {
                    let pick = at(&uploads, next(8));
                    let upload = &mut uploads[pick];
                    let (kind, status) = if next(2) == 0 {
                        (Kind::PutResult, 0)
                    } else {
                        (Kind::PutError, Status::PermissionDenied as u16)
                    };
                    let terminal = reply(upload.id, &requests, kind, |reply| reply.status = status);
                    let _ = core.receive(&mut requests, SESSION, &terminal, step);
                    upload.decided = true;
                }
                5 => {
                    let pick = next(SLOTS as u64) as usize;
                    if holds.len() < 2
                        && let Some(piece) = core.slots()[pick].piece()
                    {
                        let bytes = piece.bytes().to_vec();
                        let (tag, index) = named(&bytes);
                        holds.push((piece.hold().unwrap(), tag, index, bytes));
                    } else if !holds.is_empty() {
                        holds.swap_remove(pick % holds.len());
                    }
                }
                6 if !uploads.is_empty() => {
                    let pick = at(&uploads, next(8));
                    let upload = &uploads[pick];
                    let held = holds.iter().any(|(_, tag, _, _)| *tag == upload.tag);
                    let closed = core.close(&mut requests, upload.id);
                    assert_eq!(closed, upload.decided && !held, "seed {seed} step {step}");
                    if closed {
                        uploads.swap_remove(pick);
                    }
                }
                _ => core.tick(&mut requests, step),
            }
            for (hold, _, _, bytes) in &holds {
                assert_eq!(hold.bytes(), &bytes[..], "seed {seed} step {step}");
            }
            // While every slot holds a live fragment, the undecided upload that took the last one holds the fragment its receipt base waits for, so its next send can advance the base.
            if live_total(&uploads) == SLOTS
                && let Some(upload) = uploads
                    .iter()
                    .find(|upload| Some(upload.tag) == last && !upload.decided)
            {
                full_states += 1;
                assert!(
                    upload.live(upload.base),
                    "the last slot's taker holds its base, seed {seed} step {step}"
                );
            }
            let pieces: Vec<_> = core
                .slots()
                .iter()
                .filter_map(|slot| slot.piece())
                .collect();
            for upload in &uploads {
                for &index in upload.supplied.iter().filter(|&&at| upload.live(at)) {
                    let found: Vec<_> = pieces
                        .iter()
                        .filter(|piece| named(piece.bytes()) == (upload.tag, index))
                        .collect();
                    assert_eq!(found.len(), 1, "seed {seed} step {step}");
                    assert_eq!(
                        found[0].bytes(),
                        tagged(upload.tag, index, upload.len(index))
                    );
                }
            }
        }
        drop(holds);
    }
    assert!(full_states > 0, "the schedules reach a full pool");
}

fn supply_all(
    scene: &mut Scene<'_, '_>,
    id: super::requests::RequestId,
    object: &[u8],
    turns: u64,
) {
    let count = object.len().div_ceil(8192) as u32;
    let mut next = 0;
    for _ in 0..turns {
        while next < count {
            let start = next as usize * 8192;
            let piece = &object[start..object.len().min(start + 8192)];
            if scene.clients[0].supply(id, next, piece).is_err() {
                break;
            }
            next += 1;
        }
        drive(scene, 1);
        if scene.clients[0].put_outcome(id).is_some() {
            break;
        }
    }
}

/// A DATA frame left unsent because the session's send sequence ran out counts as dropped, as a PUT control frame does, and the upload ends `Unknown`.
#[test]
fn a_data_frame_past_the_send_sequence_counts_as_dropped() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(8192, 71);
        let id = upload(&mut scene, 6, &object, 30_000_000);
        assert_eq!(scene.clients[0].supply(id, 0, &object), Ok(8192));
        scene.clients[0]
            .sessions_mut()
            .set_send(PeerId(0), u64::MAX);
        let report = scene.clients[0].poll(scene.turn * 100);
        assert_eq!((report.sent, report.dropped), (0, 1), "{report:?}");
        assert_eq!(
            scene.clients[0].put_outcome(id),
            Some(UploadOutcome::Unknown)
        );
    });
}

#[test]
fn an_upload_streams_its_fragments_and_publishes_the_exact_bytes() {
    for len in [8192, 3 * 8192 - 100, 6 * 8192] {
        scene(&PRINCIPALS, |mut scene| {
            let object = payload(len, len as u64);
            let id = upload(&mut scene, 6, &object, 30_000_000);
            supply_all(&mut scene, id, &object, 400);
            assert_eq!(
                scene.clients[0].put_outcome(id),
                Some(UploadOutcome::Published)
            );
            drive(&mut scene, 4);
            assert!(scene.clients[0].retire(id));
            assert_eq!(held(&scene), 0);
            assert_eq!(scene.nets[0].borrow().report(1).altered, 0);
            assert_eq!(scene.fetch(6), object);
        });
    }
}

/// The owner and client 0 under eight session slots, client 0 sending `batch` datagrams per poll with a one-fragment GET window, so seven GETs and one PUT fit its table.
fn pressured(batch: u32) -> (OwnerConfig, ClientConfig) {
    let caps = Caps {
        slots: 8,
        window: 4,
    };
    let owner = OwnerConfig {
        caps,
        serve: ServeConfig {
            slots: 8,
            ..super::owner_tests::OWNER.serve
        },
        ..super::owner_tests::OWNER
    };
    let base = super::owner_tests::client_config(0);
    let client = ClientConfig {
        caps,
        fetch: FetchConfig {
            window: 1,
            ..base.fetch
        },
        batch,
        ..base
    };
    (owner, client)
}

/// Supplies upload `id`'s fragments of `object` from `next` while a source slot is free and returns the next unsupplied index.
fn supply_from<'m>(
    client: &mut Client<'m, LinkEnd<'m>>,
    id: RequestId,
    object: &[u8],
    mut next: u32,
) -> u32 {
    while (next as usize) * FRAGMENT < object.len()
        && client.supply(id, next, fragment(object, next)).is_ok()
    {
        next += 1;
    }
    next
}

/// Polls of [`pressured`]'s scene at `batch` from the first supply of a 6-fragment upload to its `Published`, with no GET in flight.
fn unpressured_publication_polls(batch: u32) -> u64 {
    let (owner, client) = pressured(batch);
    let mut polls = 0;
    scene_with_client(owner, client, 4, &PRINCIPALS, |mut scene| {
        let object = payload(6 * FRAGMENT, 77);
        let id = upload(&mut scene, 6, &object, 30_000_000);
        let mut next = 0;
        while scene.clients[0].put_outcome(id).is_none() {
            assert!(polls < 2_000, "the unpressured upload ends");
            scene.turn_with(&mut [(Actor::Client(0), &mut |clients, _, now| {
                next = supply_from(&mut clients[0], id, &object, next);
                let _ = clients[0].poll(now);
            })]);
            polls += 1;
        }
        assert_eq!(
            scene.clients[0].put_outcome(id),
            Some(UploadOutcome::Published)
        );
    });
    polls
}

/// Runs [`pressured`]'s schedule at `batch` sends per poll: client 0 holds at least two due GET frames at the start of every poll, beside a granted 6-fragment upload with no PUT control frame due. Asserts that a poll starting with a fragment due sends DATA within `b_put_send` polls, that due GET frames go out within `b_put_send` polls, and that the upload publishes its exact bytes within `unpressured_publication_polls(batch) + lag` polls.
///
/// Schedule: [`pressured`]'s owner and client 0, the owner granting 4 fragments and client 0 holding 4 source slots, links without faults and 100 µs per turn. Each turn, before client 0's poll, the test retires every decided GET, opens GETs of an absent key until client 0 refuses one, and supplies every fragment a free source slot admits; the owner answers each GET with an ERROR, which decides it.
fn publish_beside_gets(batch: u32, b_put_send: u64, lag: u64) {
    let b_put_publish = unpressured_publication_polls(batch) + lag;
    let (owner, client) = pressured(batch);
    scene_with_client(owner, client, 4, &PRINCIPALS, |mut scene| {
        let object = payload(6 * FRAGMENT, 77);
        let id = upload(&mut scene, 6, &object, 30_000_000);
        let (_, base, grant) = scene.clients[0].put_receipt(id).unwrap();
        assert_eq!(
            (base, grant),
            (0, 4),
            "the owner granted the upload before the GETs"
        );
        let crc = Crc32c::detect();
        let (mut gets, mut sent_gets) = (Vec::new(), std::collections::HashSet::new());
        let (mut next, mut data_sent, mut polls) = (0, 0u32, 0);
        let (mut put_frames, mut pressured_polls) = (0, 0);
        // Consecutive polls that started with a fragment due and sent no DATA, and that started with GET frames due and sent none.
        let (mut data_wait, mut get_wait) = (0, 0);
        while scene.clients[0].put_outcome(id).is_none() {
            assert!(
                polls < b_put_publish,
                "the upload timed out unpublished after {polls} polls"
            );
            scene.turn_with(&mut [(Actor::Client(0), &mut |clients, nets, now| {
                let client = &mut clients[0];
                gets.retain(|get| client.outcome(*get).is_none() || !client.retire(*get));
                while let Ok(get) = client.get(key(200), 0, 1 << 20, now, 30_000_000) {
                    gets.push(get);
                }
                next = supply_from(client, id, &object, next);
                let (_, _, grant) = client.put_receipt(id).unwrap();
                let due = data_sent < next.min(grant);
                let due_gets = gets
                    .iter()
                    .filter(|get| {
                        client.outcome(**get).is_none()
                            && !sent_gets.contains(&client.get_wire(**get).unwrap())
                    })
                    .count();
                pressured_polls += u64::from(due_gets >= 2);
                let _ = client.poll(now);
                let (mut data_now, mut gets_now) = (0, 0);
                nets[0].borrow_mut().retain(1, |bytes| {
                    let header = parse(crc, bytes, false).unwrap().header();
                    match header.kind {
                        Kind::Get => {
                            sent_gets.insert(header.request);
                            gets_now += 1;
                        }
                        Kind::PutData => {
                            assert_eq!(header.index, data_sent, "fragments go out once, in order");
                            data_sent += 1;
                            data_now += 1;
                        }
                        _ => put_frames += 1,
                    }
                    true
                });
                data_wait = if due && data_now == 0 { data_wait + 1 } else { 0 };
                get_wait = if gets_now == 0 { get_wait + 1 } else { 0 };
                assert!(
                    data_wait < b_put_send,
                    "a due fragment beside {due_gets} due GETs waited {data_wait} polls at turn {now}"
                );
                assert!(
                    get_wait < b_put_send,
                    "{due_gets} due GETs waited {get_wait} polls at turn {now}"
                );
            })]);
            polls += 1;
        }
        assert_eq!(
            scene.clients[0].put_outcome(id),
            Some(UploadOutcome::Published),
            "the upload's terminal"
        );
        assert_eq!(data_sent, 6);
        assert_eq!(put_frames, 0, "no PUT control frame was due");
        assert_eq!(
            pressured_polls, polls,
            "every poll started with two due GETs"
        );
        drive(&mut scene, 40);
        assert!(scene.clients[0].retire(id));
        for get in gets {
            assert!(scene.clients[0].outcome(get).is_some() && scene.clients[0].retire(get));
        }
        assert_eq!(
            scene.fetch(6),
            object,
            "the owner holds the exact supplied bytes"
        );
    });
}

/// [`publish_beside_gets`] at two sends per poll.
///
/// `B_put_send` = 1 poll: the GETs leave the upload core one of the two sends whenever it may have a frame due, no control frame is due to take it, and every send is accepted, so a poll that starts with a fragment due sends one, and the other send carries a due GET.
///
/// `B_put_publish` = `U + 5` polls, where `U` is [`unpressured_publication_polls`] at the same batch: an unpressured poll may send two fragments where a pressured poll sends one, and a fragment sent `d` polls late delays the receipt and grant it enables by `d` polls, so fragment `k` goes out at most `k` polls later than without GETs. Client 0 sends at most two GETs per poll, so the owner answers at most two GETs per turn within its batch of 8 and its reply ring of 8, and its write, receipt and RESULT path after the last fragment, fragment 5, is unchanged.
#[test]
fn put_data_is_sent_and_published_beside_gets_due_every_poll() {
    publish_beside_gets(2, 1, 5);
}

/// [`publish_beside_gets`] at one send per poll, where the GET and upload cores take the lone send in turn.
///
/// `B_put_send` = 2 polls: each poll whose lone send both cores may claim gives it to the core the previous such poll passed over, so a due fragment and due GETs each wait at most one poll.
///
/// `B_put_publish` = `U + 6` polls, where `U` is [`unpressured_publication_polls`] at the same batch: the unpressured run sends one fragment per poll and the pressured run sends one per two contested polls, so fragment 0 may wait one poll and each later fragment adds at most one more, and fragment `k` goes out at most `k + 1` polls later than without GETs. The path after fragment 5 is unchanged, as at two sends.
#[test]
fn a_lone_send_alternates_between_put_data_and_due_gets() {
    publish_beside_gets(1, 2, 6);
}

/// Polls of a one-source-slot scene from the supply of a 1-fragment upload to its `Published`.
fn one_fragment_publication_polls() -> u64 {
    let mut polls = 0;
    scene_with_client(
        super::owner_tests::OWNER,
        super::owner_tests::client_config(0),
        1,
        &PRINCIPALS,
        |mut scene| {
            let object = payload(FRAGMENT, 90);
            let id = upload(&mut scene, 6, &object, 30_000_000);
            assert_eq!(scene.clients[0].supply(id, 0, &object), Ok(FRAGMENT));
            while scene.clients[0].put_outcome(id).is_none() {
                assert!(polls < 2_000, "the one-fragment upload ends");
                drive(&mut scene, 1);
                polls += 1;
            }
            assert_eq!(
                scene.clients[0].put_outcome(id),
                Some(UploadOutcome::Published)
            );
        },
    );
    polls
}

/// Witness `one-source-index-one-first`: a client with one source slot offers fragment 1 of a 2-fragment upload first. The supply is refused naming fragment 0 and changes nothing; fragment 0 takes the slot, the owner's receipt frees it, fragment 1 takes it, and the upload publishes its exact bytes within `B_prefix` polls of the first admitted supply.
///
/// Geometry and schedule: the default owner and client 0 with one source slot, links without faults and 100 µs per turn; each poll after fragment 0's supply offers fragment 1 until a supply admits it.
///
/// `B_prefix` = `2 * U` polls, where `U` is [`one_fragment_publication_polls`], a 1-fragment upload's publication in the same scene: one slot carries the two fragments one after the other, fragment 0's supply-to-receipt cycle takes at most a whole one-fragment publication, and fragment 1's cycle then is one.
#[test]
fn one_source_slot_takes_the_prefix_first_and_publishes() {
    let b_prefix = 2 * one_fragment_publication_polls();
    scene_with_client(
        super::owner_tests::OWNER,
        super::owner_tests::client_config(0),
        1,
        &PRINCIPALS,
        |mut scene| {
            let object = payload(2 * FRAGMENT, 91);
            let id = upload(&mut scene, 6, &object, 30_000_000);
            let before = scene.clients[0].upload_snapshot(id);
            assert_eq!(
                scene.clients[0].supply(id, 1, fragment(&object, 1)),
                Err(SupplyRefused::Prefix(0))
            );
            assert_eq!(
                scene.clients[0].upload_snapshot(id),
                before,
                "the refusal changes nothing"
            );
            assert_eq!(
                scene.clients[0].supply(id, 0, fragment(&object, 0)),
                Ok(FRAGMENT)
            );
            let (mut polls, mut second) = (0, false);
            while scene.clients[0].put_outcome(id).is_none() {
                assert!(
                    polls < b_prefix,
                    "the upload timed out unpublished after {polls} polls"
                );
                if !second {
                    match scene.clients[0].supply(id, 1, fragment(&object, 1)) {
                        Ok(_) => second = true,
                        refused => assert_eq!(
                            refused,
                            Err(SupplyRefused::Slots),
                            "fragment 0 holds the one slot"
                        ),
                    }
                }
                drive(&mut scene, 1);
                polls += 1;
            }
            assert!(second, "fragment 1 took the freed slot");
            assert_eq!(
                scene.clients[0].put_outcome(id),
                Some(UploadOutcome::Published)
            );
            drive(&mut scene, 4);
            assert!(scene.clients[0].retire(id));
            assert_eq!(scene.fetch(6), object, "the owner holds the exact bytes");
        },
    );
}

/// Four source slots shared by three uploads, the test injecting the owner's receipts and results: upload A supplies fragments 3, 2 and 1 of five, leaving one slot free, and its out-of-order fragment 4 is refused naming 0. Upload B's fragment 0 takes the last slot; upload C's fragment 0 waits for a slot and takes the one B's receipt frees. B and C publish, then A supplies 0, its receipt of fragments 0 to 3 frees the slot fragment 4 takes, and A publishes.
#[test]
fn shared_source_slots_let_every_upload_publish() {
    let shared = arena(4);
    let mut budget = EngineBudget::new(1 << 20);
    let slots = sources(&shared, 4, &mut budget).unwrap();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut requests =
        ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let config = UploadConfig {
        retry_us: 1 << 40,
        attempts: 3,
    };
    let mut core = UploadCore::new(config, slots, &mut requests, &mut budget).unwrap();
    let objects = [payload(5 * 8192, 92), payload(8192, 93), payload(8192, 94)];
    let mut ready = |name: u8, object: &[u8]| {
        let id = core
            .put(
                &mut requests,
                SESSION,
                key(name),
                CacheVersion(0),
                0,
                1 << 40,
            )
            .unwrap();
        let _ = sent(&mut core, &mut requests, 0);
        let authority = reply(id, &requests, Kind::PutAuthority, |_| {});
        assert!(core.receive(&mut requests, SESSION, &authority, 0));
        core.prepare(&mut requests, id, 0, object.len() as u32, TTL_MS)
            .unwrap();
        let _ = sent(&mut core, &mut requests, 0);
        let count = object.len().div_ceil(8192) as u32;
        let ready = reply(id, &requests, Kind::PutReady, |reply| reply.grant = count);
        assert!(core.receive(&mut requests, SESSION, &ready, 0));
        id
    };
    let [a, b, c] = [6, 7, 8].map(|name| ready(name, &objects[usize::from(name - 6)]));
    let piece = |upload: usize, index: u32| fragment(&objects[upload], index);
    // The owner receipts every fragment of `id` and publishes it.
    let publish = |core: &mut UploadCore<'_>, requests: &mut ClientRequests<'_>, id, count| {
        let _ = staged(core, requests, 8);
        let ack = reply(id, requests, Kind::PutAck, |reply| {
            reply.index = count;
            reply.grant = count;
        });
        assert!(core.receive(requests, SESSION, &ack, 0));
        let result = reply(id, requests, Kind::PutResult, |_| {});
        assert!(core.receive(requests, SESSION, &result, 0));
        assert_eq!(core.outcome(requests, id), Some(UploadOutcome::Published));
    };
    for index in [3, 2, 1] {
        assert_eq!(
            core.supply(&mut requests, a, index, piece(0, index)),
            Ok(8192)
        );
    }
    assert_eq!(
        core.supply(&mut requests, a, 4, piece(0, 4)),
        Err(SupplyRefused::Prefix(0)),
        "the last slot waits for A's prefix"
    );
    assert_eq!(core.supply(&mut requests, b, 0, piece(1, 0)), Ok(8192));
    assert_eq!(
        core.supply(&mut requests, c, 0, piece(2, 0)),
        Err(SupplyRefused::Slots)
    );
    publish(&mut core, &mut requests, b, 1);
    assert_eq!(core.supply(&mut requests, c, 0, piece(2, 0)), Ok(8192));
    publish(&mut core, &mut requests, c, 1);
    assert_eq!(core.supply(&mut requests, a, 0, piece(0, 0)), Ok(8192));
    let _ = staged(&mut core, &mut requests, 8);
    let ack = reply(a, &requests, Kind::PutAck, |reply| {
        reply.index = 4;
        reply.grant = 5;
    });
    assert!(core.receive(&mut requests, SESSION, &ack, 0));
    assert_eq!(core.supply(&mut requests, a, 4, piece(0, 4)), Ok(8192));
    publish(&mut core, &mut requests, a, 5);
    for id in [a, b, c] {
        assert!(core.close(&mut requests, id));
    }
    assert!(core.slots().iter().all(|slot| slot.piece().is_none()));
}

#[test]
fn lost_data_and_a_lost_result_recover_with_the_same_bytes() {
    lost_data_and_result(false);
}

/// The control for the RESULT retry: after the first RESULT is lost the link also drops every PREPARE the client
/// sends, so no retry reaches the owner and no RESULT is replayed, as with a client that stops its timer once the
/// receipt is full.
#[test]
#[should_panic(expected = "the first RESULT dropped and a retry replayed it")]
fn negative_control_retries_lost_after_the_dropped_result_replay_no_result() {
    lost_data_and_result(true);
}

/// Loses the first DATA and the first RESULT of a two-fragment upload and checks that the retries publish the same
/// bytes; `retries_lost` also drops every PREPARE the client sends once the first RESULT is lost.
fn lost_data_and_result(retries_lost: bool) {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(2 * 8192, 40);
        let id = upload(&mut scene, 6, &object, 30_000_000);
        scene.clients[0].supply(id, 0, &object[..8192]).unwrap();
        scene.clients[0].supply(id, 1, &object[8192..]).unwrap();
        scene.clients[0].poll(scene.turn * 100);
        let (mut data_frames, mut dropped) = (0, 0);
        scene.nets[0].borrow_mut().retain(1, |bytes| {
            let data = kind_of(bytes) == Some(Kind::PutData);
            let lost = data && dropped == 0;
            data_frames += usize::from(data);
            dropped += usize::from(lost);
            !lost
        });
        assert_eq!(
            (data_frames, dropped),
            (2, 1),
            "the first poll queued both DATA fragments and the link lost the first"
        );
        let results = Cell::new(0);
        let lost_prepares = Cell::new(0);
        // The first RESULT leaves the link toward the client right after
        // the owner's poll that sends it, before the client can take it.
        for _ in 0..400 {
            scene.turn_then(
                &mut [(Actor::Client(0), &mut |clients, nets, now| {
                    let _ = clients[0].poll(now);
                    if retries_lost && results.get() > 0 {
                        nets[0].borrow_mut().retain(1, |bytes| {
                            let prepare = kind_of(bytes) == Some(Kind::PutPrepare);
                            lost_prepares.set(lost_prepares.get() + usize::from(prepare));
                            !prepare
                        });
                    }
                })],
                &mut |_, nets| {
                    nets[0].borrow_mut().retain(0, |bytes| {
                        let result = kind_of(bytes) == Some(Kind::PutResult);
                        results.set(results.get() + usize::from(result));
                        !(result && results.get() == 1)
                    });
                },
            );
            if scene.clients[0].put_outcome(id).is_some() {
                break;
            }
        }
        let results = results.get();
        if retries_lost {
            assert!(
                lost_prepares.get() > 0,
                "the link lost a PREPARE retry after the lost RESULT"
            );
        }
        assert!(
            results >= 2,
            "the first RESULT dropped and a retry replayed it"
        );
        assert_eq!(
            scene.clients[0].put_outcome(id),
            Some(UploadOutcome::Published)
        );
        assert_eq!(scene.nets[0].borrow().report(1).altered, 0);
        assert_eq!(scene.fetch(6), object);
    });
}

#[test]
fn a_slot_frees_only_after_both_its_receipt_and_its_device_return() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(8192, 41);
        scene.nets[0]
            .borrow_mut()
            .set_tx_release(TxRelease::Withheld);
        let id = upload(&mut scene, 6, &object, 30_000_000);
        supply_all(&mut scene, id, &object, 400);
        assert_eq!(
            scene.clients[0].put_outcome(id),
            Some(UploadOutcome::Published)
        );
        assert_eq!(held(&scene), 1, "receipt alone leaves the device reference");
        assert!(!scene.clients[0].retire(id));
        scene.nets[0].borrow_mut().release_tx();
        drive(&mut scene, 1);
        assert_eq!(held(&scene), 0);
        assert!(scene.clients[0].retire(id));
    });
}

/// Cancel ends the upload's retention, but the device reference keeps the sent fragment's slot held with its bytes fixed until the device returns it.
#[test]
fn a_cancel_keeps_a_device_held_source_and_its_bytes_until_the_device_returns_them() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(2 * 8192, 44);
        scene.nets[0]
            .borrow_mut()
            .set_tx_release(TxRelease::Withheld);
        let id = upload(&mut scene, 6, &object, 30_000_000);
        scene.clients[0].supply(id, 0, &object[..8192]).unwrap();
        drive(&mut scene, 1);
        scene.clients[0].cancel(id);
        drive(&mut scene, 40);
        assert_eq!(
            scene.clients[0].put_outcome(id),
            Some(UploadOutcome::Failed(Status::Cancelled))
        );
        let kept: Vec<_> = scene.clients[0]
            .sources()
            .iter()
            .filter(|slot| slot.piece().is_some())
            .collect();
        assert_eq!(kept.len(), 1, "the device-held fragment keeps its slot");
        assert!(kept[0].device_held());
        assert_eq!(kept[0].bytes(), &object[..8192]);
        assert!(!scene.clients[0].retire(id));
        scene.nets[0].borrow_mut().release_tx();
        drive(&mut scene, 1);
        assert_eq!(held(&scene), 0);
        assert!(scene.clients[0].retire(id));
    });
}

/// Session replacement after a DATA send the NIC still references and the
/// owner has receipted: the upload ends Unknown with its receipt base past
/// the fragment, so the device alone keeps the source. The source keeps its
/// bytes and its slot through the replacement and a successor upload on the
/// new session, which takes the free slots and publishes its own bytes; the
/// old slot frees only when the NIC returns it, and the old request retires
/// only after abandon and that return.
#[test]
fn a_replaced_uploads_device_held_source_outlives_the_replacement_and_its_successor() {
    scene(&PRINCIPALS, |mut scene| {
        let old = payload(2 * 8192, 53);
        scene.nets[0]
            .borrow_mut()
            .set_tx_release(TxRelease::Withheld);
        let id = upload(&mut scene, 6, &old, 30_000_000);
        scene.clients[0].supply(id, 0, &old[..8192]).unwrap();
        drive(&mut scene, 1);
        assert_eq!(held(&scene), 1);
        scene.reopen(0);
        assert_eq!(
            scene.clients[0].put_outcome(id),
            Some(UploadOutcome::Unknown),
            "a possible send decides Unknown"
        );
        assert_eq!(
            scene.clients[0].put_receipt(id).map(|(_, base, _)| base),
            Some(1),
            "fragment 0 is receipted at the decision, so the device alone keeps its slot"
        );
        let device_held = |scene: &Scene<'_, '_>| {
            scene.clients[0]
                .sources()
                .iter()
                .find(|slot| slot.device_held())
                .map(|slot| slot.bytes().to_vec())
        };
        assert_eq!(held(&scene), 1, "the device-held source keeps its slot");
        assert_eq!(device_held(&scene).as_deref(), Some(&old[..8192]));
        assert!(
            !scene.clients[0].retire(id),
            "an unknown upload waits for abandon"
        );
        // A successor on the new session publishes its own bytes from the free
        // slots while the old source stays held.
        scene.nets[0]
            .borrow_mut()
            .set_tx_release(TxRelease::AtDelivery);
        let new = payload(8192, 54);
        let successor = upload(&mut scene, 7, &new, 30_000_000);
        supply_all(&mut scene, successor, &new, 400);
        assert_eq!(
            scene.clients[0].put_outcome(successor),
            Some(UploadOutcome::Published)
        );
        assert_eq!(held(&scene), 1, "the old source is still device-held");
        assert_eq!(
            device_held(&scene).as_deref(),
            Some(&old[..8192]),
            "the old bytes stay immutable"
        );
        assert!(scene.clients[0].abandon(id));
        assert!(
            !scene.clients[0].retire(id),
            "a device-held source releases on the NIC's return"
        );
        scene.nets[0].borrow_mut().release_tx();
        drive(&mut scene, 2);
        assert_eq!(held(&scene), 0, "the NIC's return frees the old slot");
        assert!(scene.clients[0].retire(id));
        assert_eq!(scene.fetch(7), new);
        assert_eq!(scene.read(1, 6, 0).0, Some(super::fetch::Outcome::Missing));
    });
}

/// Each source slot of client 0 that holds a piece: whether a device still reads it, and its bytes.
fn source_pieces(scene: &Scene<'_, '_>) -> Vec<(bool, Vec<u8>)> {
    scene.clients[0]
        .sources()
        .iter()
        .filter(|slot| slot.piece().is_some())
        .map(|slot| (slot.device_held(), slot.bytes().to_vec()))
        .collect()
}

/// What [`decided_upload`] showed, step by step.
#[derive(Debug, Default, PartialEq, Eq)]
struct Decided {
    supplied: bool,
    /// The slots holding a piece after the fragment's DATA frame was sent.
    sent: Vec<(bool, Vec<u8>)>,
    /// The upload's outcome once its session was replaced.
    outcome: Option<UploadOutcome>,
    /// The client's cumulative receipt base for the upload at that decision.
    receipt_base: Option<u32>,
    /// The slots holding a piece at that decision.
    decided: Vec<(bool, Vec<u8>)>,
    retired_before_abandon: bool,
    abandoned: bool,
    /// Whether `retire` released the request right after `abandon`.
    retired_after_abandon: bool,
    /// The slots holding a piece after `abandon`.
    kept: Vec<(bool, Vec<u8>)>,
    /// The slots holding a piece after the link returned its references and the client took one turn.
    returned: Vec<(bool, Vec<u8>)>,
    retired_after_return: bool,
}

/// Sends fragment 0 of a two-fragment upload under `release` over a link that drops every PUT ACK, replaces the client's session, abandons the upload, then has the link return every reference it holds and gives the client one turn. With every PUT ACK dropped the client's receipt base stays at fragment 0, so the `Unknown` decision alone ends the retention of the fragment's slot.
fn decided_upload(release: TxRelease, object: &[u8]) -> Decided {
    let mut seen = Decided::default();
    scene(&PRINCIPALS, |mut scene| {
        let unreceipted = vec![Rule::new(Selector::Kind(Kind::PutAck), Effect::Drop)];
        let chain = Chain::new(unreceipted, &[], &MANIFEST).expect("one rule fits the manifest");
        scene.nets[0].borrow_mut().set_rules(chain);
        scene.nets[0].borrow_mut().set_tx_release(release);
        let id = upload(&mut scene, 6, object, 30_000_000);
        seen.supplied = scene.clients[0].supply(id, 0, &object[..FRAGMENT]) == Ok(FRAGMENT);
        drive(&mut scene, 1);
        seen.sent = source_pieces(&scene);
        scene.reopen(0);
        seen.outcome = scene.clients[0].put_outcome(id);
        seen.receipt_base = scene.clients[0].put_receipt(id).map(|(_, base, _)| base);
        seen.decided = source_pieces(&scene);
        seen.retired_before_abandon = scene.clients[0].retire(id);
        seen.abandoned = scene.clients[0].abandon(id);
        seen.retired_after_abandon = scene.clients[0].retire(id);
        seen.kept = source_pieces(&scene);
        scene.nets[0].borrow_mut().release_tx();
        drive(&mut scene, 1);
        seen.returned = source_pieces(&scene);
        seen.retired_after_return = scene.clients[0].retire(id);
    });
    seen
}

/// With device returns withheld and no receipt past fragment 0, the fragment's slot stays held with the supplied bytes through the `Unknown` decision and through `abandon`, `retire` refuses while the device reads it, and the device's return frees it.
#[test]
fn an_unknown_upload_keeps_its_device_held_source_until_the_device_returns_it() {
    let object = payload(2 * FRAGMENT, 91);
    let seen = decided_upload(TxRelease::Withheld, &object);
    let held = vec![(true, object[..FRAGMENT].to_vec())];
    assert!(seen.supplied, "the client took fragment 0");
    assert_eq!(seen.sent, held, "the link holds the sent fragment's source");
    assert_eq!(
        seen.outcome,
        Some(UploadOutcome::Unknown),
        "a possible send decides Unknown"
    );
    assert_eq!(
        seen.receipt_base,
        Some(0),
        "the receipt base stays at fragment 0, so the decision alone ends its slot's retention"
    );
    assert_eq!(
        seen.decided, held,
        "the decision keeps the slot the device still reads, with the supplied bytes"
    );
    assert!(
        !seen.retired_before_abandon,
        "an Unknown upload waits for abandon"
    );
    assert!(seen.abandoned, "abandon accepts an Unknown upload");
    assert!(
        !seen.retired_after_abandon,
        "retire refuses while the device reads a source of the upload"
    );
    assert_eq!(
        seen.kept, held,
        "abandon leaves the device-held slot and its bytes"
    );
    assert_eq!(seen.returned, vec![], "the device's return frees the slot");
    assert!(
        seen.retired_after_return,
        "the upload retires once the device returned its source"
    );
}

/// Every reference returns at delivery, so the decision frees the fragment's slot and the upload retires at `abandon`.
#[test]
fn an_unknown_upload_frees_a_source_no_device_reads() {
    let object = payload(2 * FRAGMENT, 92);
    let seen = decided_upload(TxRelease::AtDelivery, &object);
    assert!(seen.supplied, "the client took fragment 0");
    assert_eq!(
        seen.outcome,
        Some(UploadOutcome::Unknown),
        "a possible send decides Unknown"
    );
    assert_eq!(
        seen.receipt_base,
        Some(0),
        "the receipt base stays at fragment 0, so the decision alone ends its slot's retention"
    );
    assert_eq!(
        seen.decided,
        vec![],
        "no device reads the fragment, so the decision frees its slot"
    );
    assert!(
        !seen.retired_before_abandon,
        "an Unknown upload waits for abandon"
    );
    assert!(seen.abandoned, "abandon accepts an Unknown upload");
    assert!(
        seen.retired_after_abandon,
        "nothing is device-held, so the upload retires"
    );
    assert_eq!(seen.returned, vec![], "no slot holds a piece at the end");
}

#[test]
fn a_session_replacement_after_a_send_is_unknown_until_abandoned() {
    replaced_session(true);
}

/// The control for the unknown outcome: the upload's deadline passes before any send call took its BEGIN, so it is
/// `NotStarted` when its session is replaced, the outcome an upload reports when it ignores the send that reached
/// a frame.
#[test]
#[should_panic(expected = "a sent upload is Unknown after its session's replacement")]
fn negative_control_an_unsent_upload_is_not_started_at_its_replacement() {
    replaced_session(false);
}

/// Replaces client 0's session after an upload began: once the owner answered its sent BEGIN and the upload is
/// prepared when `sent` is set, and once its deadline passed before any send call took its BEGIN otherwise. The
/// scenario asserts that the upload is `Unknown` until abandoned.
fn replaced_session(sent: bool) {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(8192, 42);
        let id = if sent {
            upload(&mut scene, 6, &object, 30_000_000)
        } else {
            let now = scene.turn * 100;
            let id = scene.clients[0]
                .put(key(6), CacheVersion(0), now, 0)
                .unwrap();
            scene.clients[0].poll(now);
            assert_eq!(
                scene.clients[0].put_outcome(id),
                Some(UploadOutcome::NotStarted),
                "the deadline decided the unsent upload"
            );
            id
        };
        scene.reopen(0);
        assert_eq!(
            scene.clients[0].put_outcome(id),
            Some(UploadOutcome::Unknown),
            "a sent upload is Unknown after its session's replacement"
        );
        assert!(
            !scene.clients[0].retire(id),
            "an unknown upload waits for abandon"
        );
        assert!(scene.clients[0].abandon(id));
        assert!(scene.clients[0].retire(id));
    });
}

#[test]
fn a_cancel_after_a_send_ends_through_the_owner() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(2 * 8192, 43);
        let id = upload(&mut scene, 6, &object, 30_000_000);
        scene.clients[0].supply(id, 0, &object[..8192]).unwrap();
        drive(&mut scene, 1);
        scene.clients[0].cancel(id);
        assert_eq!(
            scene.clients[0].supply(id, 1, &object[8192..]),
            Err(SupplyRefused::NotReady)
        );
        drive(&mut scene, 40);
        assert_eq!(
            scene.clients[0].put_outcome(id),
            Some(UploadOutcome::Failed(Status::Cancelled))
        );
        let now = scene.turn * 100;
        let unsent = scene.clients[0]
            .put(key(7), CacheVersion(0), now, 30_000_000)
            .unwrap();
        scene.clients[0].cancel(unsent);
        assert_eq!(
            scene.clients[0].put_outcome(unsent),
            Some(UploadOutcome::NotStarted)
        );
    });
}

#[test]
fn refused_lost_and_reordered_sends_still_publish_the_exact_bytes() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(6 * 8192 - 7, 44);
        let id = upload(&mut scene, 6, &object, 30_000_000);
        let faults = super::link::Faults {
            loss: 15,
            duplicate: 10,
            reorder: 20,
            would_block: 30,
            ..super::link::Faults::default()
        };
        scene.nets[0].borrow_mut().set_faults(1, faults);
        scene.nets[0]
            .borrow_mut()
            .set_faults(0, super::link::Faults { loss: 15, ..faults });
        supply_all(&mut scene, id, &object, 4_000);
        assert_eq!(
            scene.clients[0].put_outcome(id),
            Some(UploadOutcome::Published)
        );
        let report = scene.nets[0].borrow().report(1);
        assert!(report.blocked > 0, "{report:?}");
        assert_eq!(report.altered, 0);
        scene.nets[0]
            .borrow_mut()
            .set_faults(1, super::link::Faults::default());
        scene.nets[0]
            .borrow_mut()
            .set_faults(0, super::link::Faults::default());
        assert_eq!(scene.fetch(6), object);
    });
}

#[test]
fn close_returns_the_transport_with_device_references_held() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(2 * 8192, 45);
        scene.nets[0]
            .borrow_mut()
            .set_tx_release(TxRelease::Withheld);
        let id = upload(&mut scene, 6, &object, 30_000_000);
        scene.clients[0].supply(id, 0, &object[..8192]).unwrap();
        scene.clients[0].supply(id, 1, &object[8192..]).unwrap();
        drive(&mut scene, 6);
        let net = scene.nets[0].clone();
        let held = net.borrow().nic_held();
        assert!(held > 0);
        let [client, _] = scene.clients;
        let (_, transport) = client.close(scene.turn * 100);
        assert_eq!(
            net.borrow().nic_held(),
            held,
            "close keeps every device reference"
        );
        net.borrow_mut().release_tx();
        assert_eq!(net.borrow().nic_held(), 0);
        drop(transport);
    });
}

#[test]
fn an_upload_beyond_the_peer_share_fails_typed() {
    scene(&PRINCIPALS, |mut scene| {
        let first = payload(2 * 8192, 46);
        let a = upload(&mut scene, 6, &first, 30_000_000);
        let now = scene.turn * 100;
        let b = scene.clients[0]
            .put(key(7), CacheVersion(0), now, 30_000_000)
            .unwrap();
        drive(&mut scene, 4);
        assert_eq!(
            scene.clients[0].put_outcome(b),
            Some(UploadOutcome::Failed(Status::RequestPressure))
        );
        scene.clients[0].supply(a, 0, &first[..8192]).unwrap();
        scene.clients[0].supply(a, 1, &first[8192..]).unwrap();
        drive(&mut scene, 40);
        assert_eq!(
            scene.clients[0].put_outcome(a),
            Some(UploadOutcome::Published)
        );
    });
}

#[test]
fn a_device_return_before_the_receipt_keeps_the_slot() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(2 * 8192, 47);
        let id = upload(&mut scene, 6, &object, 30_000_000);
        scene.clients[0].supply(id, 0, &object[..8192]).unwrap();
        scene.clients[0].supply(id, 1, &object[8192..]).unwrap();
        // The ACKs and RESULTs leave the link toward the client right after
        // the owner's poll that sends them, before the client can take them.
        for _ in 0..20 {
            drive_then(&mut scene, 1, &mut |_, nets| {
                nets[0].borrow_mut().retain(0, |bytes| {
                    !matches!(kind_of(bytes), Some(Kind::PutAck | Kind::PutResult))
                });
            });
        }
        assert_eq!(
            scene.nets[0].borrow().nic_held(),
            0,
            "the device returned both"
        );
        assert_eq!(held(&scene), 2, "the receipt still holds both slots");
        assert_eq!(
            scene.clients[0].supply(id, 0, &object[..8192]),
            Err(SupplyRefused::Index)
        );
        drive(&mut scene, 40);
        assert_eq!(
            scene.clients[0].put_outcome(id),
            Some(UploadOutcome::Published)
        );
        assert_eq!(held(&scene), 0);
        assert_eq!(scene.fetch(6), object);
    });
}

#[test]
fn a_receipt_mask_bit_keeps_its_slot_until_the_base_passes() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(3 * 8192, 48);
        let id = upload(&mut scene, 6, &object, 30_000_000);
        for index in 0..3 {
            let start = index as usize * 8192;
            scene.clients[0]
                .supply(id, index, &object[start..start + 8192])
                .unwrap();
        }
        let crc = Crc32c::detect();
        let mut masked = false;
        // DATA 0 leaves the link toward the owner right after the client's
        // poll sends it, and the owner's ACKs are read right after the poll
        // that sends them, so neither end can take them first.
        for _ in 0..20 {
            scene.turn_then(
                &mut [(Actor::Client(0), &mut |clients, nets, now| {
                    clients[0].poll(now);
                    nets[0].borrow_mut().retain(1, |bytes| {
                        parse(crc, bytes, false).ok().is_none_or(|frame| {
                            let header = frame.header();
                            !(header.kind == Kind::PutData && header.index == 0)
                        })
                    });
                })],
                &mut |_, nets| {
                    nets[0].borrow_mut().retain(0, |bytes| {
                        if let Ok(frame) = parse(crc, bytes, false) {
                            let header = frame.header();
                            masked |= header.kind == Kind::PutAck && header.offset != 0;
                        }
                        true
                    });
                },
            );
        }
        assert!(masked, "the owner named fragments above the base");
        assert_eq!(held(&scene), 3);
        drive(&mut scene, 60);
        assert_eq!(
            scene.clients[0].put_outcome(id),
            Some(UploadOutcome::Published)
        );
        assert_eq!(scene.fetch(6), object);
    });
}

#[derive(Default)]
struct Oracle {
    published: std::collections::BTreeMap<u8, Vec<u8>>,
    absent: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
enum Breach {
    Altered(u64),
    Wrong(u8, Option<super::fetch::Outcome>),
    Present(u8, Option<super::fetch::Outcome>),
}

impl Oracle {
    fn record(&mut self, name: u8, object: &[u8], outcome: Option<UploadOutcome>) {
        match outcome {
            Some(UploadOutcome::Published) => {
                self.published.insert(name, object.to_vec());
            }
            Some(UploadOutcome::Failed(_) | UploadOutcome::NotStarted) => self.absent.push(name),
            other => panic!("key {name}: no settled outcome to check, {other:?}"),
        }
    }

    fn check(&self, scene: &mut Scene<'_, '_>) -> Result<(), Breach> {
        let altered: u64 = scene
            .nets
            .iter()
            .map(|net| {
                (0..2)
                    .map(|side| net.borrow().report(side).altered)
                    .sum::<u64>()
            })
            .sum();
        if altered > 0 {
            return Err(Breach::Altered(altered));
        }
        for (&name, object) in &self.published {
            let (outcome, bytes) = scene.read(1, name, 1 << 16);
            if outcome != Some(super::fetch::Outcome::Complete) || bytes != *object {
                return Err(Breach::Wrong(name, outcome));
            }
        }
        for &name in &self.absent {
            let (outcome, _) = scene.read(1, name, 1 << 16);
            if outcome != Some(super::fetch::Outcome::Missing) {
                return Err(Breach::Present(name, outcome));
            }
        }
        Ok(())
    }
}

/// Full receipt with the record's writes held: every fragment is acknowledged
/// and its source slot freed, the upload stays undecided and the key
/// unreadable, payload writes ending alone publish nothing, and only the header
/// write's terminal publishes the bytes the oracle reads back exact.
#[test]
fn a_full_receipt_with_its_final_write_held_publishes_only_after_the_release() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(2 * FRAGMENT, 46);
        let id = upload(&mut scene, 7, &object, 30_000_000);
        let before = write_tokens(&scene.control).len();
        for index in 0..2 {
            assert!(
                scene.clients[0]
                    .supply(id, index, fragment(&object, index))
                    .is_ok()
            );
        }
        // Each write is held right after the owner's poll submits it,
        // before a device tick can run it.
        let mut held_writes = Vec::new();
        for _ in 0..40 {
            drive_then(&mut scene, 1, &mut |control, _| {
                for token in write_tokens(control).split_off(before + held_writes.len()) {
                    control.hold(token);
                    held_writes.push(token);
                }
            });
        }
        assert!(
            held_writes.len() > 1,
            "payload and header writes: {held_writes:?}"
        );
        assert_eq!(held(&scene), 0, "full receipt freed every source slot");
        assert_eq!(scene.clients[0].put_outcome(id), None);
        assert!(!scene.visible(7));
        let header = held_writes.pop().unwrap();
        for &token in &held_writes {
            scene.control.release(token);
        }
        drive(&mut scene, 20);
        assert_eq!(
            scene.clients[0].put_outcome(id),
            None,
            "the header write is held"
        );
        assert!(!scene.visible(7));
        scene.control.release(header);
        drive(&mut scene, 40);
        assert_eq!(
            scene.clients[0].put_outcome(id),
            Some(UploadOutcome::Published)
        );
        let mut oracle = Oracle::default();
        oracle.record(7, &object, scene.clients[0].put_outcome(id));
        assert_eq!(oracle.check(&mut scene), Ok(()));
    });
}

fn fragment(object: &[u8], index: u32) -> &[u8] {
    let start = index as usize * FRAGMENT;
    &object[start..object.len().min(start + FRAGMENT)]
}

#[test]
fn metadata_across_fragments_and_a_multi_command_body_reach_the_oracle() {
    metadata_reaches_the_oracle(8_999);
}

/// The control for the metadata cap: the GET's cap equals the object's 9,000 metadata bytes, so the GET completes.
#[test]
#[should_panic(expected = "a GET whose metadata cap is below the object's metadata fails TooLarge")]
fn negative_control_a_metadata_cap_that_fits_serves_the_get() {
    metadata_reaches_the_oracle(9_000);
}

/// Publishes an object with 9,000 metadata bytes across fragments and a multi-command body, checks it against
/// the oracle, and reads it back with `metadata_cap`, which must refuse the read as `TooLarge`.
fn metadata_reaches_the_oracle(metadata_cap: u32) {
    let storage = crate::storage::owner_fixture::storage_with_metadata(9_000);
    let config = super::owner_tests::OWNER;
    super::put_tests::scene_over(storage, config, &PRINCIPALS, |mut scene| {
        let object = payload(9_000 + 30_000, 50);
        let writes = scene.owner.volume_report().writes_submitted;
        let id = shaped(&mut scene, 6, 9_000, &object, 30_000_000);
        supply_all(&mut scene, id, &object, 600);
        let mut oracle = Oracle::default();
        oracle.record(6, &object, scene.clients[0].put_outcome(id));
        assert_eq!(scene.owner.volume_report().writes_submitted - writes, 3);
        oracle.check(&mut scene).unwrap();
        let (outcome, capped) = scene.read(0, 6, metadata_cap);
        if metadata_cap >= 9_000 {
            assert_eq!(
                outcome,
                Some(super::fetch::Outcome::Complete),
                "a GET whose cap holds the metadata is served"
            );
        }
        assert_eq!(
            outcome,
            Some(super::fetch::Outcome::Failed(Status::TooLarge)),
            "a GET whose metadata cap is below the object's metadata fails TooLarge"
        );
        assert!(capped.is_empty(), "the 9,000 bytes are metadata");
    });
}

#[test]
fn mixed_gets_and_lossy_uploads_hold_every_bound() {
    scene(&PRINCIPALS, |mut scene| {
        let faults = Faults {
            loss: 10,
            duplicate: 10,
            reorder: 20,
            delay: 3,
            would_block: 20,
            ..Faults::default()
        };
        scene.nets[0].borrow_mut().set_faults(1, faults);
        scene.nets[0].borrow_mut().set_faults(0, faults);
        let crc = Crc32c::detect();
        let commands = super::owner_tests::OWNER.put.commands as u64;
        let mut oracle = Oracle::default();
        let (mut peak_writes, mut peak_held, mut gets) = (0, 0, 0);
        for round in 0..4u8 {
            let object = payload(
                4 * FRAGMENT + 100 * usize::from(round),
                u64::from(round) + 60,
            );
            let count = object.len().div_ceil(FRAGMENT) as u32;
            let name = 10 + round;
            let id = upload(&mut scene, name, &object, 30_000_000);
            let now = scene.turn * 100;
            let extra = scene.clients[0]
                .put(key(40), CacheVersion(0), now, 30_000_000)
                .unwrap();
            let mut reads = None;
            let (mut next, mut grant) = (0, count.min(4));
            let eager = round % 2 == 1;
            for turn in 0..6_000u32 {
                while next < count && (eager || turn % 5 == 0) {
                    if scene.clients[0]
                        .supply(id, next, fragment(&object, next))
                        .is_err()
                    {
                        break;
                    }
                    next += 1;
                    if !eager {
                        break;
                    }
                }
                let read = match reads {
                    Some(read) => read,
                    None => {
                        gets += 1;
                        let read = scene.clients[1]
                            .get(key(1), 0, 1 << 20, scene.turn * 100, 30_000_000)
                            .unwrap();
                        reads = Some(read);
                        read
                    }
                };
                let granted = grant;
                scene.turn_with(&mut [
                    (Actor::Client(1), &mut |clients, _, now| {
                        clients[1].poll(now);
                        while clients[1].take(read).is_some() {}
                        if clients[1].outcome(read).is_some() && clients[1].retire(read) {
                            reads = None;
                        }
                    }),
                    (Actor::Client(0), &mut |clients, _, now| {
                        clients[0].poll(now);
                    }),
                    (Actor::Harness(0), &mut |_, nets, _| {
                        nets[0].borrow_mut().retain(1, |bytes| {
                            if let Ok(frame) = parse(crc, bytes, false)
                                && frame.header().kind == Kind::PutData
                            {
                                assert!(frame.header().index < granted, "DATA within the grant");
                            }
                            true
                        });
                    }),
                ]);
                scene.nets[0].borrow_mut().retain(0, |bytes| {
                    if let Ok(frame) = parse(crc, bytes, false)
                        && matches!(frame.header().kind, Kind::PutAck | Kind::PutReady)
                    {
                        grant = grant.max(frame.header().grant);
                    }
                    true
                });
                let volume = scene.owner.volume_report();
                let writes = volume.writes_submitted - volume.writes_done - volume.writes_failed;
                assert!(writes <= commands, "{writes} writes in flight");
                peak_writes = peak_writes.max(writes);
                peak_held = peak_held.max(held(&scene));
                if scene.clients[0].put_outcome(id).is_some() {
                    break;
                }
            }
            if eager {
                assert_eq!(peak_held, 4, "an eager supplier fills every source slot");
            }
            oracle.record(name, &object, scene.clients[0].put_outcome(id));
            assert_eq!(
                scene.clients[0].put_outcome(extra),
                Some(UploadOutcome::Failed(Status::RequestPressure)),
                "the peer's PUT share holds"
            );
            assert!(scene.clients[0].retire(extra));
            drive(&mut scene, 20);
            assert!(scene.clients[0].retire(id));
            if let Some(read) = reads {
                for _ in 0..400 {
                    scene.turn_with(&mut [
                        (Actor::Client(1), &mut |clients, _, now| {
                            clients[1].poll(now);
                            while clients[1].take(read).is_some() {}
                        }),
                        (Actor::Client(0), &mut |clients, _, now| {
                            clients[0].poll(now);
                        }),
                    ]);
                    if scene.clients[1].outcome(read).is_some() {
                        assert!(scene.clients[1].retire(read));
                        break;
                    }
                }
            }
        }
        scene.nets[0].borrow_mut().set_faults(1, Faults::default());
        scene.nets[0].borrow_mut().set_faults(0, Faults::default());
        drive(&mut scene, 40);
        assert!(gets > 4, "GETs ran beside every upload");
        assert!(peak_writes > 0);
        assert_eq!(held(&scene), 0);
        let volume = scene.owner.volume_report();
        assert_eq!(volume.writes_submitted, volume.writes_done);
        assert_eq!(volume.writes_failed, 0);
        assert_eq!(scene.owner.report().defects, 0);
        assert_eq!(oracle.published.len(), 4);
        oracle.check(&mut scene).unwrap();
    });
}

#[test]
fn a_short_write_cancel_and_invalidation_leave_their_keys_absent() {
    let statuses = [Status::DeviceError, Status::Cancelled, Status::Contended];
    for (case, status) in statuses.into_iter().enumerate() {
        scene(&PRINCIPALS, |mut scene| {
            let object = payload(2 * FRAGMENT, 70 + case as u64);
            let id = upload(&mut scene, 6, &object, 30_000_000);
            scene.clients[0]
                .supply(id, 0, fragment(&object, 0))
                .unwrap();
            scene.clients[0]
                .supply(id, 1, fragment(&object, 1))
                .unwrap();
            // The short-write case faults each write right after the owner's
            // poll submits it, before a device tick can run it. A write the
            // device's profile qualifies lands whole or not at all, so the
            // device fails it with an error status in place of a short count.
            let mut seen = scene.control.events().len();
            let (mut held, mut held_seen) = (Vec::new(), seen);
            let mut short = |control: &SimControl| {
                let events = control.events();
                for event in &events[seen..] {
                    if let Event::Submitted(token, Operation::Write) = *event
                        && control.try_fault(token, Fault::Short { units: 1 }).is_err()
                    {
                        control.fault(
                            token,
                            Fault::Status(crate::storage::DeviceStatus::Kernel(-5)),
                        );
                    }
                }
                seen = events.len();
            };
            // The cancel case holds each write at its submission, so the fill stays unpublished until the cancel
            // reaches the owner under every round order.
            let mut hold = |control: &SimControl| {
                let events = control.events();
                for event in &events[held_seen..] {
                    if let Event::Submitted(token, Operation::Write) = *event {
                        control.hold(token);
                        held.push(token);
                    }
                }
                held_seen = events.len();
            };
            let mut writing = false;
            for _ in 0..20 {
                drive_then(&mut scene, 1, &mut |control, _| match case {
                    0 => short(control),
                    1 => hold(control),
                    _ => {}
                });
                let volume = scene.owner.volume_report();
                if volume.writes_submitted > volume.writes_done {
                    writing = true;
                    break;
                }
            }
            assert!(writing, "the case acts during writes");
            match case {
                0 => {
                    for _ in 0..19 {
                        drive_then(&mut scene, 1, &mut |control, _| short(control));
                    }
                    drive(&mut scene, 1);
                }
                1 => {
                    scene.clients[0].cancel(id);
                    drive(&mut scene, 20);
                    for token in held {
                        scene.control.release(token);
                    }
                }
                _ => {
                    let mut budget = crate::storage::WorkBudget::new(1 << 12);
                    scene.owner.invalidate(&key(6), 4, &mut budget).unwrap();
                }
            }
            drive(&mut scene, 200);
            assert_eq!(
                scene.clients[0].put_outcome(id),
                Some(UploadOutcome::Failed(status)),
                "case {case}"
            );
            let mut oracle = Oracle::default();
            oracle.record(6, &object, scene.clients[0].put_outcome(id));
            oracle.check(&mut scene).unwrap();
            assert!(scene.clients[0].retire(id));
        });
    }
}

#[test]
fn a_claimed_success_without_publication_fails_the_oracle() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(2 * FRAGMENT, 80);
        let id = upload(&mut scene, 6, &object, 30_000_000);
        scene.clients[0]
            .supply(id, 0, fragment(&object, 0))
            .unwrap();
        drive(&mut scene, 20);
        assert_eq!(
            scene.clients[0].put_outcome(id),
            None,
            "half an upload stays open"
        );
        let mut premature = Oracle::default();
        premature.record(1, &payload(1000, 1), Some(UploadOutcome::Published));
        premature.check(&mut scene).unwrap();
        premature.record(6, &object, Some(UploadOutcome::Published));
        // The oracle's GET joins the open upload's fill and waits for it.
        assert_eq!(premature.check(&mut scene), Err(Breach::Wrong(6, None)));
    });
}

#[test]
fn early_slot_reuse_fails_the_oracle() {
    for release in [TxRelease::AtDelivery, TxRelease::Premature] {
        scene(&PRINCIPALS, |mut scene| {
            let object = payload(6 * FRAGMENT, 81);
            let faults = Faults {
                duplicate: 100,
                delay: 200,
                ..Faults::default()
            };
            scene.nets[0].borrow_mut().set_faults(1, faults);
            scene.nets[0].borrow_mut().set_tx_release(release);
            let id = upload(&mut scene, 6, &object, 30_000_000);
            supply_all(&mut scene, id, &object, 3_000);
            assert_eq!(
                scene.clients[0].put_outcome(id),
                Some(UploadOutcome::Published)
            );
            let mut oracle = Oracle::default();
            oracle.record(6, &object, scene.clients[0].put_outcome(id));
            let verdict = oracle.check(&mut scene);
            if release == TxRelease::Premature {
                assert!(matches!(verdict, Err(Breach::Altered(_))), "{verdict:?}");
            } else {
                assert_eq!(verdict, Ok(()));
            }
        });
    }
}

#[test]
fn resent_fragments_add_no_credit() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(3 * FRAGMENT, 82);
        let id = upload(&mut scene, 6, &object, 30_000_000);
        for index in 0..3 {
            scene.clients[0]
                .supply(id, index, fragment(&object, index))
                .unwrap();
        }
        let crc = Crc32c::detect();
        let (mut resent, delivered, mut acks) = (0, RefCell::new([0u32; 3]), 0);
        // The client's DATA is filtered and counted right after the poll
        // that sends it, and the owner's ACKs are checked right after the
        // poll that sends them, so neither end can take them first.
        for turn in 0..1_000 {
            let hold = turn < 200;
            scene.turn_then(
                &mut [(Actor::Client(0), &mut |clients, nets, now| {
                    clients[0].poll(now);
                    let mut delivered = delivered.borrow_mut();
                    nets[0].borrow_mut().retain(1, |bytes| {
                        let Ok(frame) = parse(crc, bytes, false) else {
                            return true;
                        };
                        let header = frame.header();
                        if header.kind != Kind::PutData {
                            return true;
                        }
                        if hold && header.index == 0 {
                            return false;
                        }
                        let at = header.index as usize;
                        resent += u32::from(delivered[at] > 0);
                        delivered[at] += 1;
                        true
                    });
                })],
                &mut |_, nets| {
                    let prefix = delivered
                        .borrow()
                        .iter()
                        .take_while(|&&count| count > 0)
                        .count() as u32;
                    nets[0].borrow_mut().retain(0, |bytes| {
                        if let Ok(frame) = parse(crc, bytes, false)
                            && frame.header().kind == Kind::PutAck
                        {
                            acks += 1;
                            assert!(
                                frame.header().index <= prefix,
                                "base {} above the delivered prefix {prefix}",
                                frame.header().index
                            );
                        }
                        true
                    });
                },
            );
            if scene.clients[0].put_outcome(id).is_some() {
                break;
            }
        }
        assert!(
            resent > 0 && acks > 0,
            "fragments 1 and 2 were resent with fresh sequences"
        );
        let mut oracle = Oracle::default();
        oracle.record(6, &object, scene.clients[0].put_outcome(id));
        oracle.check(&mut scene).unwrap();
    });
}

#[test]
fn an_owner_close_during_writes_ends_the_upload_unknown_and_frees_its_slots() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(3 * FRAGMENT, 83);
        let id = upload(&mut scene, 6, &object, 30_000_000);
        for index in 0..3u32 {
            scene.clients[0]
                .supply(id, index, fragment(&object, index))
                .unwrap();
        }
        let mut writing = false;
        for _ in 0..20 {
            drive(&mut scene, 1);
            let volume = scene.owner.volume_report();
            if volume.writes_submitted > volume.writes_done {
                writing = true;
                break;
            }
        }
        assert!(writing, "the owner closes during writes");
        scene.owner.close(scene.turn * 100);
        for _ in 0..2_000 {
            drive(&mut scene, 1);
            if scene.owner.blockers().is_none() && scene.clients[0].put_outcome(id).is_some() {
                break;
            }
        }
        assert!(
            scene.owner.blockers().is_none(),
            "the closed owner holds no live request and its volume quiesced"
        );
        assert_eq!(
            scene.clients[0].put_outcome(id),
            Some(UploadOutcome::Unknown)
        );
        assert!(
            !scene.clients[0].retire(id),
            "an unknown upload waits for abandon"
        );
        assert!(scene.clients[0].abandon(id));
        drive(&mut scene, 4);
        assert_eq!(held(&scene), 0);
        assert!(scene.clients[0].retire(id));
    });
}

fn sourced_core<'a>(
    arena: &'a crate::storage::BufferArena<crate::storage::owner_fixture::TestPlatform>,
    requests: &mut ClientRequests<'a>,
) -> UploadCore<'a> {
    let slots = sources(arena, 8, &mut EngineBudget::new(1 << 20)).unwrap();
    let config = UploadConfig {
        retry_us: 1_000,
        attempts: 3,
    };
    UploadCore::new(config, slots, requests, &mut EngineBudget::new(1 << 20)).unwrap()
}

fn ready(
    core: &mut UploadCore<'_>,
    requests: &mut ClientRequests<'_>,
    name: u8,
    grant: u32,
) -> RequestId {
    let id = core
        .put(requests, SESSION, key(name), CacheVersion(0), 0, 1_000_000)
        .unwrap();
    sent(core, requests, 0);
    let wire = requests.upload(id).unwrap().wire();
    let authority = Header {
        allocation: 5,
        ..header(Kind::PutAuthority, wire, key(name))
    };
    assert!(core.receive(requests, SESSION, &authority, 0));
    core.prepare(requests, id, 0, 3 * 8192, TTL_MS).unwrap();
    sent(core, requests, 0);
    let ready = Header {
        allocation: 5,
        grant,
        ..manifest_reply(Kind::PutReady, wire, key(name), 3 * 8192)
    };
    assert!(core.receive(requests, SESSION, &ready, 0));
    id
}

/// A `kind` reply from the owner for request `wire` and `key`, carrying the manifest of a body of `total` bytes under serial 5, as the owner names a prepared upload.
fn manifest_reply(kind: Kind, wire: u64, key: [u8; 32], total: u32) -> Header {
    super::serve::manifest_header(
        kind,
        wire,
        key,
        &super::serve::Manifest {
            allocation: 5,
            metadata_len: 0,
            body_len: total,
        },
    )
}

fn staged(
    core: &mut UploadCore<'_>,
    requests: &mut ClientRequests<'_>,
    budget: usize,
) -> Vec<(u64, u32)> {
    let mut frames = Vec::new();
    core.data(requests, budget, |_, header, _, _| {
        frames.push((header.request, header.index));
        true
    });
    frames
}

#[test]
fn data_rotates_across_uploads_and_a_masked_ack_resends_only_its_holes() {
    let shared = arena(8);
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut requests = ClientRequests::new(
        RequestTable::new(4, 1, 4),
        &releases,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    let mut core = sourced_core(&shared, &mut requests);
    let a = ready(&mut core, &mut requests, 6, 3);
    let b = ready(&mut core, &mut requests, 7, 3);
    let object = payload(3 * 8192, 90);
    for id in [a, b] {
        for index in 0..3u32 {
            let start = index as usize * 8192;
            core.supply(&mut requests, id, index, &object[start..start + 8192])
                .unwrap();
        }
    }
    assert!(core.wake(&requests).0, "supplied DATA is due");
    let (wa, wb) = (
        requests.upload(a).unwrap().wire(),
        requests.upload(b).unwrap().wire(),
    );
    let first = staged(&mut core, &mut requests, 2);
    let wires: std::collections::BTreeSet<_> = first.iter().map(|frame| frame.0).collect();
    assert_eq!(wires, [wa, wb].into(), "one fragment from each upload");
    assert_eq!(staged(&mut core, &mut requests, 8).len(), 4);
    assert!(!core.wake(&requests).0);
    let ack = Header {
        allocation: 5,
        index: 0,
        offset: 0b11,
        grant: 3,
        ..manifest_reply(Kind::PutAck, wa, key(6), 3 * 8192)
    };
    assert!(core.receive(&mut requests, SESSION, &ack, 10));
    assert_eq!(staged(&mut core, &mut requests, 8), [(wa, 0)]);
    let gap = Header {
        offset: 0b10,
        ..ack
    };
    assert!(core.receive(&mut requests, SESSION, &gap, 2_000));
    assert_eq!(staged(&mut core, &mut requests, 8), [(wa, 0), (wa, 1)]);
}

#[test]
fn data_passes_skip_idle_uploads_and_resume_after_the_last_staged() {
    let shared = arena(8);
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut requests = ClientRequests::new(
        RequestTable::new(4, 1, 4),
        &releases,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    let mut core = sourced_core(&shared, &mut requests);
    let a = ready(&mut core, &mut requests, 6, 3);
    core.put(
        &mut requests,
        SESSION,
        key(8),
        CacheVersion(0),
        0,
        1_000_000,
    )
    .unwrap();
    let c = ready(&mut core, &mut requests, 7, 3);
    let object = payload(3 * 8192, 96);
    for id in [a, c] {
        for index in 0..3u32 {
            let start = index as usize * 8192;
            core.supply(&mut requests, id, index, &object[start..start + 8192])
                .unwrap();
        }
    }
    let (wa, wc) = (
        requests.upload(a).unwrap().wire(),
        requests.upload(c).unwrap().wire(),
    );
    assert_eq!(
        staged(&mut core, &mut requests, 4),
        [(wa, 0), (wc, 0), (wa, 1), (wc, 1)]
    );
    assert_eq!(staged(&mut core, &mut requests, 1), [(wa, 2)]);
    assert_eq!(staged(&mut core, &mut requests, 8), [(wc, 2)]);
    assert_eq!(staged(&mut core, &mut requests, 8), []);
}

/// Mask bits are relative to the ACK's own base, so the client applies a mask only from an ACK at or above the upload's base; a reordered ACK below it leaves the resend set as it was.
#[test]
fn a_reordered_ack_below_the_base_resends_nothing() {
    let shared = arena(8);
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut requests = ClientRequests::new(
        RequestTable::new(4, 1, 4),
        &releases,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    let mut core = sourced_core(&shared, &mut requests);
    let id = ready(&mut core, &mut requests, 6, 3);
    let object = payload(3 * 8192, 99);
    for index in 0..3u32 {
        let start = index as usize * 8192;
        core.supply(&mut requests, id, index, &object[start..start + 8192])
            .unwrap();
    }
    let wire = requests.upload(id).unwrap().wire();
    assert_eq!(staged(&mut core, &mut requests, 8).len(), 3);
    let newer = Header {
        allocation: 5,
        index: 1,
        offset: 0b1,
        grant: 3,
        ..manifest_reply(Kind::PutAck, wire, key(6), 3 * 8192)
    };
    assert!(core.receive(&mut requests, SESSION, &newer, 10));
    assert_eq!(staged(&mut core, &mut requests, 8), [(wire, 1)]);
    let older = Header {
        index: 0,
        offset: 0b10,
        ..newer
    };
    assert!(core.receive(&mut requests, SESSION, &older, 20));
    assert_eq!(staged(&mut core, &mut requests, 8), []);
}

#[test]
fn due_fragments_across_mark_words_send_lowest_first() {
    const SLOTS: u32 = 130;
    let shared = arena(SLOTS);
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut requests = ClientRequests::new(
        RequestTable::new(4, 1, 4),
        &releases,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    let slots = sources(&shared, SLOTS, &mut EngineBudget::new(1 << 20)).unwrap();
    let config = UploadConfig {
        retry_us: 1_000,
        attempts: 3,
    };
    let mut core = UploadCore::new(
        config,
        slots,
        &mut requests,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    let id = core
        .put(
            &mut requests,
            SESSION,
            key(6),
            CacheVersion(0),
            0,
            1_000_000,
        )
        .unwrap();
    sent(&mut core, &mut requests, 0);
    let wire = requests.upload(id).unwrap().wire();
    let authority = Header {
        allocation: 5,
        ..header(Kind::PutAuthority, wire, key(6))
    };
    assert!(core.receive(&mut requests, SESSION, &authority, 0));
    core.prepare(&mut requests, id, 0, SLOTS * 8192, TTL_MS)
        .unwrap();
    sent(&mut core, &mut requests, 0);
    let ready = Header {
        allocation: 5,
        grant: SLOTS,
        ..manifest_reply(Kind::PutReady, wire, key(6), SLOTS * 8192)
    };
    assert!(core.receive(&mut requests, SESSION, &ready, 0));
    let object = payload(8192, 95);
    for index in (0..SLOTS).rev() {
        core.supply(&mut requests, id, index, &object).unwrap();
    }
    assert!(core.wake(&requests).0);
    let order: Vec<u32> = staged(&mut core, &mut requests, SLOTS as usize)
        .into_iter()
        .map(|(_, index)| index)
        .collect();
    assert_eq!(order, (0..SLOTS).collect::<Vec<_>>());
    assert!(!core.wake(&requests).0);
    let ack = Header {
        allocation: 5,
        index: 65,
        offset: 0b10,
        grant: SLOTS,
        ..manifest_reply(Kind::PutAck, wire, key(6), SLOTS * 8192)
    };
    assert!(core.receive(&mut requests, SESSION, &ack, 10));
    assert_eq!(
        staged(&mut core, &mut requests, 8),
        [(wire, 65), (wire, 66)],
        "the holes at the base and below the named fragment resend, across mark words"
    );
}

#[test]
fn data_above_the_grant_waits_and_is_not_due() {
    let shared = arena(8);
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut requests = ClientRequests::new(
        RequestTable::new(4, 1, 4),
        &releases,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    let mut core = sourced_core(&shared, &mut requests);
    let id = ready(&mut core, &mut requests, 6, 1);
    let object = payload(2 * 8192, 91);
    core.supply(&mut requests, id, 0, &object[..8192]).unwrap();
    core.supply(&mut requests, id, 1, &object[8192..]).unwrap();
    let wire = requests.upload(id).unwrap().wire();
    assert_eq!(staged(&mut core, &mut requests, 8), [(wire, 0)]);
    assert!(
        !core.wake(&requests).0,
        "a fragment above the grant is not due"
    );
    let idle = Header {
        allocation: 5,
        grant: 1,
        ..manifest_reply(Kind::PutReady, wire, key(6), 3 * 8192)
    };
    for at in 1..6 {
        core.tick(&mut requests, at * 1_000 + 1);
        assert!(core.receive(&mut requests, SESSION, &idle, at * 1_000 + 2));
        sent(&mut core, &mut requests, at * 1_000 + 2);
    }
    assert_eq!(
        core.outcome(&requests, id),
        None,
        "an answering owner keeps the upload live"
    );
    let ack = Header {
        allocation: 5,
        index: 1,
        grant: 2,
        ..manifest_reply(Kind::PutAck, wire, key(6), 3 * 8192)
    };
    assert!(core.receive(&mut requests, SESSION, &ack, 7_000));
    assert_eq!(staged(&mut core, &mut requests, 8), [(wire, 1)]);
}

/// READY on the last PREPARE attempt resets the attempt count, so a lost first DATA frame resends alongside a PREPARE.
#[test]
fn ready_on_the_last_prepare_attempt_restarts_the_attempts() {
    let shared = arena(8);
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut requests = ClientRequests::new(
        RequestTable::new(4, 1, 4),
        &releases,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    let mut core = sourced_core(&shared, &mut requests);
    let id = core
        .put(
            &mut requests,
            SESSION,
            key(6),
            CacheVersion(0),
            0,
            1_000_000,
        )
        .unwrap();
    assert_eq!(sent(&mut core, &mut requests, 0), [Kind::PutBegin]);
    let authority = reply(id, &requests, Kind::PutAuthority, |_| {});
    assert!(core.receive(&mut requests, SESSION, &authority, 0));
    core.prepare(&mut requests, id, 0, 3 * 8192, TTL_MS)
        .unwrap();
    for at in [0, 1_000, 2_000] {
        core.tick(&mut requests, at);
        assert_eq!(sent(&mut core, &mut requests, at), [Kind::PutPrepare]);
    }
    let ready = reply(id, &requests, Kind::PutReady, |reply| reply.grant = 3);
    assert!(core.receive(&mut requests, SESSION, &ready, 2_010));
    let object = payload(8192, 98);
    core.supply(&mut requests, id, 0, &object).unwrap();
    let wire = requests.upload(id).unwrap().wire();
    assert_eq!(staged(&mut core, &mut requests, 8), [(wire, 0)]);
    core.tick(&mut requests, 3_010);
    assert_eq!(core.outcome(&requests, id), None);
    assert_eq!(staged(&mut core, &mut requests, 8), [(wire, 0)]);
    assert_eq!(sent(&mut core, &mut requests, 3_010), [Kind::PutPrepare]);
}

#[test]
fn a_supplied_fragment_wakes_the_client_at_once() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(8192, 92);
        let id = upload(&mut scene, 6, &object, 30_000_000);
        scene.clients[0].supply(id, 0, &object).unwrap();
        assert_eq!(scene.clients[0].next_deadline_us(), Some(0));
    });
}

#[test]
fn refused_data_stays_due_for_the_next_poll() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(8192, 93);
        let id = upload(&mut scene, 6, &object, 30_000_000);
        scene.clients[0].supply(id, 0, &object).unwrap();
        let blocked = Faults {
            would_block: 100,
            ..Faults::default()
        };
        scene.nets[0].borrow_mut().set_faults(1, blocked);
        scene.clients[0].poll(scene.turn * 100);
        scene.nets[0].borrow_mut().set_faults(1, Faults::default());
        scene.clients[0].poll(scene.turn * 100 + 100);
        let mut data = 0;
        scene.nets[0].borrow_mut().retain(1, |bytes| {
            data += usize::from(kind_of(bytes) == Some(Kind::PutData));
            true
        });
        assert_eq!(data, 1);
    });
}

#[test]
fn closed_sources_keep_the_arena_until_the_device_returns_them() {
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(2 * 8192, 94);
        scene.nets[0]
            .borrow_mut()
            .set_tx_release(TxRelease::Withheld);
        let id = upload(&mut scene, 6, &object, 30_000_000);
        scene.clients[0].supply(id, 0, &object[..8192]).unwrap();
        scene.clients[0].supply(id, 1, &object[8192..]).unwrap();
        drive(&mut scene, 6);
        let net = scene.nets[0].clone();
        let sourcing = scene.sourcing;
        let [client, _] = scene.clients;
        let (_, transport) = client.close(scene.turn * 100);
        let report = sourcing.report(PoolKind::ReadResponse);
        assert!(report.free < report.count, "{report:?}");
        net.borrow_mut().release_tx();
        let report = sourcing.report(PoolKind::ReadResponse);
        assert_eq!(report.free, report.count, "{report:?}");
        drop(transport);
    });
}

/// A tag call of sixteen frames gives its last frame to the next call exactly when one frame follows it and [`KeyRing::tags`] has no vector pass, so seventeen frames tag as fifteen and a pair there and as a full pass and one frame alone with the pass. The pass is asked about only when one frame follows.
#[test]
fn a_call_of_sixteen_yields_a_frame_to_a_lone_follower_only_without_the_vector_pass() {
    assert!(yields_a_frame(1, || false));
    assert!(!yields_a_frame(1, || true));
    for after in (0..=32).filter(|&after| after != 1) {
        assert!(
            !yields_a_frame(after, || unreachable!("asked with {after} frames after")),
            "{after} frames after"
        );
    }
}

/// Forty DATA frames staged in one turn seal sixteen to a tag pass with an eight-frame remainder, and each frame authenticates with the bytes and crc of the slot it names; a frame naming no slot ends the sealed prefix there.
/// The first seventeen of them, and the first thirty-three, whose last seventeen follow a call of sixteen, seal with the tags they took among the forty. Each group of full fragments runs 132 steps of its kernel, over two middle blocks, 128 body blocks, the padding block and the outer block, so on aarch64 with `sha2` the step counts name the seventeen's three groups of four chains, one of three and a pair, and a frame hashed alone would run the one-chain kernel.
#[test]
fn sealed_data_frames_authenticate_with_their_slot_bytes() {
    use crate::isa_witness::{Kernel, detected, runs};
    const COUNT: u32 = 40;
    let shared = arena(COUNT);
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut requests = ClientRequests::new(
        RequestTable::new(4, 1, 4),
        &releases,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    let slots = sources(&shared, COUNT, &mut EngineBudget::new(1 << 20)).unwrap();
    let config = UploadConfig {
        retry_us: 1_000,
        attempts: 3,
    };
    let mut core = UploadCore::new(
        config,
        slots,
        &mut requests,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    let id = core
        .put(
            &mut requests,
            SESSION,
            key(6),
            CacheVersion(0),
            0,
            1_000_000,
        )
        .unwrap();
    sent(&mut core, &mut requests, 0);
    let wire = requests.upload(id).unwrap().wire();
    let authority = Header {
        allocation: 5,
        ..header(Kind::PutAuthority, wire, key(6))
    };
    assert!(core.receive(&mut requests, SESSION, &authority, 0));
    core.prepare(&mut requests, id, 0, COUNT * 8192, TTL_MS)
        .unwrap();
    sent(&mut core, &mut requests, 0);
    let ready = Header {
        allocation: 5,
        grant: COUNT,
        ..manifest_reply(Kind::PutReady, wire, key(6), COUNT * 8192)
    };
    assert!(core.receive(&mut requests, SESSION, &ready, 0));
    let object = payload(COUNT as usize * 8192, 96);
    for index in 0..COUNT {
        let at = index as usize * 8192;
        core.supply(&mut requests, id, index, &object[at..at + 8192])
            .unwrap();
    }
    let crc = Crc32c::detect();
    let ring = KeyRing::load(
        &PRINCIPALS[..1],
        &entries()[..1],
        1,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    let mut frames = vec![[0u8; HEADER_LEN]; COUNT as usize];
    let mut staged: Vec<Staged> = Vec::new();
    core.data(&mut requests, COUNT as usize, |epoch, ask, slot, source| {
        let header = Header {
            principal: PRINCIPALS[0],
            key_epoch: 1,
            owner_nonce: [3; 16],
            client_nonce: [4; 16],
            sequence: staged.len() as u64 + 1,
            epoch,
            ..ask
        };
        let out = &mut frames[staged.len()];
        encode_with_body_crc(crc, &header, [source.bytes(), &[]], source.crc(), out).unwrap();
        staged.push((PeerId(0), ask.request, Some(slot)));
        true
    });
    assert_eq!(staged.len(), COUNT as usize);
    let encoded = frames.clone();
    let endpoint = 0x00E1_0001;
    let sealed = seal_data(&ring, endpoint, &mut frames, (&staged, core.slots()));
    assert_eq!(sealed, COUNT as usize);
    for (index, (frame, (_, _, slot))) in frames.iter().zip(&staged).enumerate() {
        let body = core.slots()[usize::from(slot.unwrap())].bytes();
        assert_eq!(body, &object[index * 8192..(index + 1) * 8192]);
        let mut datagram = frame.to_vec();
        datagram.extend_from_slice(body);
        let parsed = parse(crc, &datagram, false).unwrap();
        assert!(parsed.check_body(crc).is_ok(), "frame {index}");
        assert!(
            ring.authenticate(&parsed, PeerId(0), endpoint, Direction::ClientToOwner)
                .is_ok(),
            "frame {index}"
        );
    }
    let sha2 = detected!(aarch64: "sha2").present;
    let kernels = [
        Kernel::Sha2One,
        Kernel::Sha2Two,
        Kernel::Sha2Three,
        Kernel::Sha2Four,
    ];
    for (count, steps) in [(17, [0, 132, 132, 3 * 132]), (33, [0, 132, 132, 7 * 132])] {
        let mut run = encoded[..count].to_vec();
        let before = kernels.map(runs);
        assert_eq!(
            seal_data(&ring, endpoint, &mut run, (&staged[..count], core.slots())),
            count
        );
        assert_eq!(run, frames[..count], "{count} frames");
        if sha2 {
            let ran: [usize; 4] = std::array::from_fn(|at| runs(kernels[at]) - before[at]);
            assert_eq!(
                ran, steps,
                "{count} frames: one-, two-, three- and four-chain steps"
            );
        }
    }
    staged[20].2 = Some(u16::MAX);
    let mut again = encoded.clone();
    assert_eq!(
        seal_data(&ring, endpoint, &mut again, (&staged, core.slots())),
        20
    );
    assert_eq!(again[..20], frames[..20], "the prefix seals as before");
    assert_eq!(
        again[20..],
        encoded[20..],
        "no frame from the failed one on is tagged"
    );
}

/// Seeded random turns of two uploads over twelve slots, against a model of which fragments occupy a slot (one the receipt has not passed, or one a device still holds) and which are due (supplied and unsent, refused by the transport, or a receipt hole not yet resent).
/// A supply succeeds exactly when the fragment is new and a slot is free, with the last free slot reserved for the lowest fragment at or above the receipt base that the upload holds no slot for; each DATA frame is its upload's lowest due fragment below the grant, with that fragment's bytes; a turn stops short only when no upload has one; the wake reports due DATA exactly when the model has some; and the bytes under a device hold stay fixed until it ends.
/// Once both uploads are receipted and every hold ends, every slot is free and both uploads retire.
#[test]
fn random_turns_keep_slot_custody_with_the_model() {
    const SLOTS: u32 = 12;
    const COUNT: u32 = 64;
    for seed in 0..40 {
        let shared = arena(SLOTS);
        let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
        let mut requests = ClientRequests::new(
            RequestTable::new(4, 1, 4),
            &releases,
            &mut EngineBudget::new(1 << 20),
        )
        .unwrap();
        let slots = sources(&shared, SLOTS, &mut EngineBudget::new(1 << 20)).unwrap();
        let config = UploadConfig {
            retry_us: 1 << 40,
            attempts: 3,
        };
        let mut core = UploadCore::new(
            config,
            slots,
            &mut requests,
            &mut EngineBudget::new(1 << 20),
        )
        .unwrap();
        let mut rng = crate::storage::seeded::SplitMix64::new(seed);
        let objects = [
            payload(COUNT as usize * 8192, seed),
            payload(COUNT as usize * 8192, seed + 99),
        ];
        let fragment = |upload: usize, index: u32| {
            let at = index as usize * 8192;
            &objects[upload][at..at + 8192]
        };
        let mut ids = Vec::new();
        for name in [6, 7] {
            let id = core
                .put(
                    &mut requests,
                    SESSION,
                    key(name),
                    CacheVersion(0),
                    0,
                    1 << 50,
                )
                .unwrap();
            sent(&mut core, &mut requests, 0);
            let wire = requests.upload(id).unwrap().wire();
            let authority = Header {
                allocation: 5,
                ..header(Kind::PutAuthority, wire, key(name))
            };
            assert!(core.receive(&mut requests, SESSION, &authority, 0));
            core.prepare(&mut requests, id, 0, COUNT * 8192, TTL_MS)
                .unwrap();
            sent(&mut core, &mut requests, 0);
            let ready = Header {
                allocation: 5,
                grant: 8,
                ..manifest_reply(Kind::PutReady, wire, key(name), COUNT * 8192)
            };
            assert!(core.receive(&mut requests, SESSION, &ready, 0));
            ids.push((id, wire));
        }
        let mut base = [0u32; 2];
        let mut grant = [8u32; 2];
        let mut held: [std::collections::BTreeSet<u32>; 2] = Default::default();
        let mut due: [std::collections::BTreeSet<u32>; 2] = Default::default();
        let mut guarded: [std::collections::BTreeSet<u32>; 2] = Default::default();
        let lowest = |due: &[std::collections::BTreeSet<u32>; 2],
                      base: &[u32; 2],
                      grant: &[u32; 2],
                      upload: usize| {
            due[upload]
                .range(base[upload]..grant[upload])
                .next()
                .copied()
        };
        let mut holds: Vec<(usize, u32, Vec<u8>, crate::storage::NicHold<'_>)> = Vec::new();
        let occupied =
            |held: &[std::collections::BTreeSet<u32>; 2],
             base: &[u32; 2],
             holds: &[(usize, u32, Vec<u8>, crate::storage::NicHold<'_>)]| {
                let mut slots: std::collections::BTreeSet<(usize, u32)> = (0..2)
                    .flat_map(|upload| {
                        held[upload]
                            .range(base[upload]..)
                            .map(move |&index| (upload, index))
                    })
                    .collect();
                slots.extend(holds.iter().map(|(upload, index, _, _)| (*upload, *index)));
                slots.len()
            };
        for turn in 0..600u64 {
            let upload = rng.below(2) as usize;
            let (id, wire) = ids[upload];
            match rng.below(5) {
                0 | 1 => {
                    let index = base[upload] + rng.below(16) as u32;
                    if index >= COUNT {
                        continue;
                    }
                    let fresh = !held[upload].contains(&index);
                    let room = SLOTS as usize - occupied(&held, &base, &holds);
                    let free = free_slots(&core, room);
                    let wanted = (base[upload]..)
                        .find(|at| !held[upload].contains(at))
                        .unwrap();
                    // A supply that finds the free list empty first reclaims returned slots, which a refusal keeps.
                    let (before, was_listed) = (core.snapshot(&requests, id), listed(&core) > 0);
                    let got = core.supply(&mut requests, id, index, fragment(upload, index));
                    if was_listed && matches!(got, Err(SupplyRefused::Prefix(_))) {
                        assert_eq!(
                            core.snapshot(&requests, id),
                            before,
                            "a prefix refusal changes nothing, seed {seed} turn {turn}"
                        );
                    }
                    let want = match (fresh, room, free) {
                        (false, ..) => Err(SupplyRefused::Index),
                        (true, 0, _) => Err(SupplyRefused::Slots),
                        (true, _, 1) if index != wanted => Err(SupplyRefused::Prefix(wanted)),
                        (true, ..) => Ok(8192),
                    };
                    assert_eq!(
                        got, want,
                        "seed {seed} turn {turn} upload {upload} index {index}"
                    );
                    if got.is_ok() {
                        held[upload].insert(index);
                        due[upload].insert(index);
                        guarded[upload].remove(&index);
                    }
                }
                2 => {
                    let budget = rng.below(4) as usize + 1;
                    let mut staged = Vec::new();
                    core.data(&mut requests, budget, |_, header, slot, _| {
                        let upload = usize::from(header.request != ids[0].1);
                        assert_eq!(
                            Some(header.index),
                            lowest(&due, &base, &grant, upload),
                            "seed {seed} turn {turn}"
                        );
                        due[upload].remove(&header.index);
                        staged.push((upload, header.index, slot));
                        true
                    });
                    if staged.len() < budget {
                        assert!(
                            (0..2).all(|upload| lowest(&due, &base, &grant, upload).is_none()),
                            "seed {seed} turn {turn}: a turn stopped with DATA due"
                        );
                    }
                    // The transport refuses a random suffix of the turn, and the device takes a reference to about half of the frames it took.
                    let refused = staged.len() - rng.below(staged.len() as u64 + 1) as usize;
                    for &(upload, index, slot) in &staged[refused..] {
                        core.unsent(&mut requests, slot);
                        due[upload].insert(index);
                    }
                    staged.truncate(refused);
                    let take = rng.next_u64();
                    for (at, (upload, index, slot)) in staged.into_iter().enumerate() {
                        let piece = core.slots()[usize::from(slot)].piece().unwrap();
                        assert_eq!(
                            piece.bytes(),
                            fragment(upload, index),
                            "seed {seed} turn {turn}"
                        );
                        if take >> at & 1 == 1 {
                            holds.push((
                                upload,
                                index,
                                piece.bytes().to_vec(),
                                piece.hold().unwrap(),
                            ));
                        }
                    }
                }
                3 => {
                    if !holds.is_empty() {
                        let (_, _, bytes, hold) =
                            holds.swap_remove(rng.below(holds.len() as u64) as usize);
                        assert_eq!(hold.bytes(), &bytes[..], "seed {seed} turn {turn}");
                    }
                }
                _ => {
                    let next = (base[upload] + rng.below(3) as u32).min(grant[upload]);
                    base[upload] = next;
                    grant[upload] = (next + 8).min(COUNT);
                    let mask = rng.below(1 << 6);
                    let ack = Header {
                        allocation: 5,
                        index: next,
                        grant: grant[upload],
                        offset: mask,
                        ..manifest_reply(Kind::PutAck, wire, key(6 + upload as u8), COUNT * 8192)
                    };
                    let _ = core.receive(&mut requests, SESSION, &ack, turn);
                    // A named hole is due again once per slot: the guard outlasts the test.
                    let named = 64 - mask.leading_zeros();
                    if named > 0 {
                        for &index in held[upload].range(next..=next + named) {
                            let rel = index - next;
                            let hole = rel == 0 || mask & 1 << (rel - 1) == 0;
                            if hole && guarded[upload].insert(index) {
                                due[upload].insert(index);
                            }
                        }
                    }
                    if rng.below(2) == 0 {
                        core.tick(&mut requests, turn);
                    }
                }
            }
            assert_eq!(
                core.wake(&requests).0,
                (0..2).any(|upload| lowest(&due, &base, &grant, upload).is_some()),
                "seed {seed} turn {turn}: the wake names due DATA"
            );
        }
        holds.clear();
        for (upload, (id, wire)) in ids.iter().enumerate() {
            let done = Header {
                allocation: 5,
                index: COUNT,
                grant: COUNT,
                ..manifest_reply(Kind::PutAck, *wire, key(6 + upload as u8), COUNT * 8192)
            };
            assert!(core.receive(&mut requests, SESSION, &done, 1_000));
            let result = Header {
                allocation: 5,
                ..manifest_reply(Kind::PutResult, *wire, key(6 + upload as u8), COUNT * 8192)
            };
            assert!(core.receive(&mut requests, SESSION, &result, 1_000));
            assert_eq!(core.outcome(&requests, *id), Some(UploadOutcome::Published));
        }
        core.tick(&mut requests, 1_001);
        assert!(
            core.slots().iter().all(|slot| slot.piece().is_none()),
            "seed {seed}"
        );
        for (id, _) in ids {
            assert!(core.close(&mut requests, id), "seed {seed}");
        }
        let report = shared.report(PoolKind::ReadResponse);
        assert_eq!(report.free, report.count - SLOTS, "seed {seed}");
    }
}

mod shared_oracle {
    use crate::oracle::{
        ActionKind, BoundaryEvent, CommandEvidence, Custodian, Incarnation, KeyId, Label,
        Obligation, Outcome, PutOutcome, Recorder, Serial, census, check,
    };

    use std::cell::RefCell;
    use std::rc::Rc;

    use super::super::adapters::{Attempt, boundary, get, tenures, write_bindings};
    use super::super::audit::Reason;
    use super::super::frame::Kind;
    use super::super::link::Draws;
    use super::super::put_tests::{Drawn, scene_drawn};
    use super::super::rules::{Capture, Chain, Decision, Effect, MANIFEST, Rule, Selector};
    use super::{
        FRAGMENT, Faults, PRINCIPALS, Scene, Status, TxRelease, UploadOutcome, drive, payload,
        scene, supply_all, upload,
    };
    use crate::sim::choice::Chooser;
    use crate::sim::entropy::{draw, nonce_site};

    fn chain(rules: Vec<Rule>, taps: &[usize]) -> Chain {
        Chain::new(rules, taps, &MANIFEST).unwrap()
    }

    /// The owner's and both clients' nonce actors, and the two link actors.
    const ACTORS: [u16; 3] = [1, 2, 3];
    const LINKS: [u16; 2] = [5, 6];

    /// Every site a drawn scene draws at.
    fn drawn_sites() -> Vec<crate::sim::choice::Site> {
        let mut sites: Vec<_> = ACTORS.map(nonce_site).to_vec();
        sites.extend(
            LINKS
                .iter()
                .flat_map(|&link| super::super::link::sites(link)),
        );
        sites
    }

    /// A scene whose boot nonces and link faults are all draws of `draws`.
    fn drawn_scene(draws: &Draws, body: impl FnOnce(Scene<'_, '_>)) {
        let nonces = ACTORS.map(|actor| {
            let mut chooser = draws.borrow_mut();
            let incarnation = chooser.launch(actor);
            let mut bytes = [0; 16];
            draw(&mut chooser, nonce_site(actor), incarnation, &mut bytes).unwrap();
            bytes
        });
        let drawn = Drawn {
            nonces,
            draws,
            links: LINKS,
        };
        let storage = crate::storage::owner_fixture::storage(8);
        let config = super::super::owner_tests::OWNER;
        scene_drawn(storage, config, &PRINCIPALS, Some(drawn), body);
    }

    /// Committed decisions on the upload's link for frames of `kind` that
    /// `picked` selects.
    fn selected(scene: &Scene<'_, '_>, kind: Kind, picked: impl Fn(&Decision) -> bool) -> usize {
        committed(scene)
            .iter()
            .filter(|capture| capture.kind == Some(kind) && picked(&capture.decision))
            .count()
    }

    /// The committed captures on the upload's link, as frame kinds, indexes
    /// and decisions.
    fn committed(scene: &Scene<'_, '_>) -> Vec<Capture> {
        let net = scene.nets[0].borrow();
        let last = net
            .rules()
            .captures()
            .iter()
            .map(|capture| capture.tap)
            .max()
            .unwrap_or(0);
        let captures = net.rules().captures().iter();
        captures
            .filter(|capture| capture.tap == last)
            .copied()
            .collect()
    }

    const LEN: u64 = 3 * FRAGMENT as u64 - 100;

    fn passes(rec: Recorder) {
        let verdict = check(&rec.finish());
        assert!(
            verdict.satisfies(&[Obligation::History, Obligation::Bytes, Obligation::Custody]),
            "{verdict:?}"
        );
    }

    #[test]
    fn a_live_upload_then_get_passes_the_shared_oracle() {
        scene(&PRINCIPALS, |mut scene| {
            let mut rec = Recorder::new(1);
            let mut tenures = tenures(&scene);
            let mut attempt =
                Attempt::begin(&mut scene, &mut rec, (6, Label(1)), LEN, &mut tenures);
            attempt.run(&mut scene, &mut rec, 600);
            assert_eq!(attempt.outcome, Some(UploadOutcome::Published));
            get(&mut scene, &mut rec, 6, Label(1));
            passes(rec);
        });
    }

    /// The publication's evidence comes from the device boundary: its write
    /// completion names every write command the device accepted for the
    /// attempt, each with the success terminal delivered into the sink, and
    /// the owner's receipt of each fragment is a receive row with that
    /// fragment's bytes; the census reconciles the capture with the rows.
    #[test]
    fn a_publication_carries_every_accepted_write_and_its_delivered_terminal() {
        scene(&PRINCIPALS, |mut scene| {
            let mut rec = Recorder::new(1);
            let mut tenures = tenures(&scene);
            let mut attempt =
                Attempt::begin(&mut scene, &mut rec, (6, Label(1)), LEN, &mut tenures);
            attempt.run(&mut scene, &mut rec, 600);
            assert_eq!(attempt.outcome, Some(UploadOutcome::Published));
            let rows = rec.rows();
            let written: Vec<_> = rows
                .iter()
                .filter(|r| r.kind == ActionKind::WriteCompleted)
                .collect();
            assert_eq!(written.len(), 1);
            let commands = written[0].commands.as_ref().expect("command evidence");
            assert!(!commands.is_empty() && commands.iter().all(|c| c.succeeded()));
            assert_eq!(written[0].serial, attempt.serial);
            let receives = rows.iter().filter(|r| r.kind == ActionKind::Receive);
            let bytes: Vec<u8> = receives
                .flat_map(|r| r.payload.clone().expect("a fragment's bytes"))
                .collect();
            assert_eq!(
                bytes, attempt.object,
                "the receipts carry the bytes in order"
            );
            let capture = scene.control.capture();
            let bindings = write_bindings(scene.owner.volume_bound());
            assert!(
                census(
                    &boundary(&capture),
                    (false, capture.accepted),
                    &bindings,
                    rows
                )
                .is_ok()
            );
            assert!(
                commands.len() > 1,
                "the attempt wrote more than one command"
            );
            get(&mut scene, &mut rec, 6, Label(1));
            passes(rec);
        });
    }

    /// A delivered terminal succeeds only when it moved its command's whole
    /// length: a kernel status short of the length is a failed write.
    #[test]
    fn a_short_write_terminal_is_a_failure() {
        use crate::storage::device::sim::{Capture, Captured};
        use crate::storage::{CommandToken, DeviceRange, DeviceStatus, Operation};
        let token = CommandToken::from_raw(7);
        let device = DeviceRange::new(0, 4096).unwrap();
        let capture = |status| Capture {
            events: vec![
                Captured::Submitted {
                    token,
                    operation: Operation::Write,
                    device,
                    host: 0,
                    ordinal: 0,
                },
                Captured::Delivered { token, status },
            ],
            overflow: false,
            accepted: 1,
        };
        let success = |status| match boundary(&capture(status))[1] {
            BoundaryEvent::Delivered { success, .. } => success,
            BoundaryEvent::Submitted { .. } => unreachable!("the second event is the terminal"),
        };
        assert!(success(DeviceStatus::Kernel(4096)));
        assert!(!success(DeviceStatus::Kernel(2048)));
        assert!(!success(DeviceStatus::Kernel(-5)));
        assert!(success(DeviceStatus::Nvme(0)));
    }

    /// Capture overflow makes write evidence incomplete, so `written_commands`
    /// rejects the capture.
    #[test]
    #[should_panic(expected = "the device capture overflowed its bound")]
    fn write_evidence_from_an_overflowed_capture_is_refused() {
        let capture = crate::storage::device::sim::Capture {
            events: Vec::new(),
            overflow: true,
            accepted: 1,
        };
        let _ = super::super::adapters::written_commands((&[], false), &capture, 1);
    }

    /// A capture that overflows its bound leaves the evidence incomplete:
    /// the adapters' census refuses to credit the run and names the
    /// overflow.
    #[test]
    #[should_panic(expected = "the device capture overflowed its bound")]
    fn a_capture_past_its_bound_blocks_credit() {
        scene(&PRINCIPALS, |mut scene| {
            scene.control.set_capture_bound(2);
            let mut rec = Recorder::new(1);
            let mut tenures = tenures(&scene);
            let mut attempt =
                Attempt::begin(&mut scene, &mut rec, (6, Label(1)), LEN, &mut tenures);
            attempt.run(&mut scene, &mut rec, 600);
        });
    }

    /// Controls on recorded evidence: a publication with its last accepted
    /// write command still held, or failed, fails eligibility; a completion
    /// under another attempt's serial fails the attempt judgment and the
    /// census's binding check; deleted, duplicated, reordered and trailing
    /// captured events and an overflowed capture fail the census.
    #[test]
    fn held_failed_and_foreign_commands_and_altered_captures_are_refused() {
        scene(&PRINCIPALS, |mut scene| {
            let mut rec = Recorder::new(1);
            let mut tenures = tenures(&scene);
            let mut attempt =
                Attempt::begin(&mut scene, &mut rec, (6, Label(1)), LEN, &mut tenures);
            attempt.run(&mut scene, &mut rec, 600);
            let rows = rec.rows().to_vec();
            let rule = "a publication before every write of its attempt delivered success";
            let altered = |change: &dyn Fn(&mut crate::oracle::Row)| {
                let mut rows = rows.clone();
                let done = rows
                    .iter_mut()
                    .find(|r| r.kind == ActionKind::WriteCompleted)
                    .expect("a write completion");
                change(done);
                check(&Recorder::rebuilt(rows)).violated()
            };
            for delivered in [None, Some(false)] {
                let violated = altered(&|done| {
                    done.commands
                        .as_mut()
                        .unwrap()
                        .last_mut()
                        .unwrap()
                        .delivered = delivered
                });
                assert_eq!(violated, Some((Obligation::History, rule)), "{delivered:?}");
            }
            let foreign =
                altered(&|done| done.serial = Serial::new(done.serial.unwrap().0.get() + 1));
            assert_eq!(
                foreign,
                Some((
                    Obligation::History,
                    "the rows of one attempt name two serials"
                )),
                "a completion under another attempt's serial discharges nothing"
            );
            let capture = scene.control.capture();
            let events = boundary(&capture);
            let bindings = write_bindings(scene.owner.volume_bound());
            let counted = capture.accepted;
            let census = |events: &[BoundaryEvent], overflow: bool, rows: &[crate::oracle::Row]| {
                census(events, (overflow, counted), &bindings, rows)
            };
            assert!(census(&events, false, &rows).is_ok());
            let mut foreign_rows = rows.clone();
            foreign_rows
                .iter_mut()
                .find(|r| r.kind == ActionKind::WriteCompleted)
                .unwrap()
                .serial = Serial::new(99);
            let gap = census(&events, false, &foreign_rows).unwrap_err();
            assert!(gap.contains("bound to another attempt"), "{gap}");
            let submitted = events
                .iter()
                .position(|e| matches!(e, BoundaryEvent::Submitted { .. }))
                .unwrap();
            let delivered = events
                .iter()
                .position(|e| matches!(e, BoundaryEvent::Delivered { .. }))
                .unwrap();
            let mut deleted = events.clone();
            deleted.remove(submitted);
            let mut duplicated = events.clone();
            duplicated.insert(delivered, events[delivered]);
            let mut reordered = events.clone();
            reordered.swap(submitted, delivered);
            for (name, broken) in [
                ("deleted", deleted),
                ("duplicated", duplicated),
                ("reordered", reordered),
            ] {
                assert!(census(&broken, false, &rows).is_err(), "{name}");
            }
            // The last accepted command and its terminal leave the capture together; the device's own count of
            // accepted commands still shows the gap.
            let last = events
                .iter()
                .rposition(|e| matches!(e, BoundaryEvent::Submitted { .. }))
                .expect("an accepted command");
            let BoundaryEvent::Submitted { token, .. } = events[last] else {
                unreachable!("rposition found a submission");
            };
            let tail: Vec<_> = events
                .iter()
                .enumerate()
                .filter(|&(at, e)| {
                    at != last
                        && !(at > last
                            && matches!(e, BoundaryEvent::Delivered { token: t, .. } if *t == token))
                })
                .map(|(_, e)| *e)
                .collect();
            let gap = census(&tail, false, &[]).unwrap_err();
            assert!(gap.contains("device counted"), "{gap}");
            assert!(
                census(&events, true, &rows).is_err(),
                "an overflowed capture"
            );
        });
    }

    #[test]
    fn a_publication_whose_write_commands_overlap_fails_history() {
        scene(&PRINCIPALS, |mut scene| {
            let mut rec = Recorder::new(1);
            let mut tenures = tenures(&scene);
            let mut attempt =
                Attempt::begin(&mut scene, &mut rec, (6, Label(1)), LEN, &mut tenures);
            attempt.run(&mut scene, &mut rec, 600);
            assert_eq!(attempt.outcome, Some(UploadOutcome::Published));
            let mut rows = rec.rows().to_vec();
            let done = rows
                .iter_mut()
                .find(|r| r.kind == ActionKind::WriteCompleted)
                .expect("a write completion");
            let commands = done.commands.as_mut().expect("command evidence");
            assert!(
                commands.len() > 1,
                "the attempt wrote more than one command"
            );
            // The second command moves onto the first's range; the lengths
            // still sum to at least the object.
            commands[1].start = commands[0].start;
            assert_eq!(
                check(&Recorder::rebuilt(rows)).violated(),
                Some((
                    Obligation::History,
                    "a publication whose write commands overlap on the device"
                ))
            );
        });
    }

    #[test]
    fn a_completion_omitting_or_repeating_a_bound_write_fails_the_census() {
        scene(&PRINCIPALS, |mut scene| {
            let mut rec = Recorder::new(1);
            let mut tenures = tenures(&scene);
            let mut attempt =
                Attempt::begin(&mut scene, &mut rec, (6, Label(1)), LEN, &mut tenures);
            attempt.run(&mut scene, &mut rec, 600);
            assert_eq!(attempt.outcome, Some(UploadOutcome::Published));
            let rows = rec.rows().to_vec();
            let capture = scene.control.capture();
            let events = boundary(&capture);
            let bindings = write_bindings(scene.owner.volume_bound());
            let census = |rows: &[crate::oracle::Row]| {
                census(&events, (false, capture.accepted), &bindings, rows)
            };
            assert!(census(&rows).is_ok());
            let altered = |change: &dyn Fn(&mut Vec<CommandEvidence>)| {
                let mut rows = rows.clone();
                let done = rows
                    .iter_mut()
                    .find(|r| r.kind == ActionKind::WriteCompleted)
                    .expect("a write completion");
                change(done.commands.as_mut().expect("command evidence"));
                rows
            };
            let recorded = rows
                .iter()
                .find(|r| r.kind == ActionKind::WriteCompleted)
                .and_then(|r| r.commands.clone())
                .expect("command evidence");
            assert!(
                recorded.len() > 1,
                "the attempt wrote more than one command"
            );
            let omitted = altered(&|commands| {
                commands.pop();
            });
            let gap = census(&omitted).unwrap_err();
            assert!(gap.contains("is not recorded"), "{gap}");
            let repeated = altered(&|commands| {
                let first = commands[0];
                let count = commands.len();
                commands.clear();
                commands.extend(std::iter::repeat_n(first, count));
            });
            let gap = census(&repeated).unwrap_err();
            assert!(gap.contains("recorded twice"), "{gap}");
            let mut absent = rows.clone();
            absent
                .iter_mut()
                .find(|r| r.kind == ActionKind::WriteCompleted)
                .expect("a write completion")
                .commands = None;
            let gap = census(&absent).unwrap_err();
            assert!(gap.contains("is not recorded"), "{gap}");
            // A write the volume never bound: the adapter would leave it out
            // of the completion, and the census must still see the captured
            // write standing without a binding.
            let unbound = recorded.last().expect("a command").token;
            let mut fewer = bindings.clone();
            fewer.retain(|&(token, _)| token != unbound);
            let gap = crate::oracle::census(
                &events,
                (false, capture.accepted),
                &fewer,
                &altered(&|commands| {
                    commands.pop();
                }),
            )
            .unwrap_err();
            assert!(gap.contains("no binding"), "{gap}");
        });
    }

    /// Lost and delayed packets on the upload's link force resends; the
    /// attempt still publishes once and the GET returns its exact bytes.
    #[test]
    fn a_live_upload_over_a_lossy_link_passes_the_shared_oracle() {
        scene(&PRINCIPALS, |mut scene| {
            let faults = Faults {
                loss: 15,
                duplicate: 15,
                reorder: 20,
                delay: 3,
                ..Faults::default()
            };
            scene.nets[0].borrow_mut().set_faults(1, faults);
            let mut rec = Recorder::new(1);
            let mut tenures = tenures(&scene);
            let mut attempt =
                Attempt::begin(&mut scene, &mut rec, (6, Label(1)), LEN, &mut tenures);
            attempt.run(&mut scene, &mut rec, 3_000);
            assert_eq!(attempt.outcome, Some(UploadOutcome::Published));
            let report = scene.nets[0].borrow().report(1);
            assert!(report.lost > 0 && report.delayed > 0, "{report:?}");
            scene.nets[0].borrow_mut().set_faults(1, Faults::default());
            get(&mut scene, &mut rec, 6, Label(1));
            passes(rec);
        });
    }

    /// Owner validation supplies receive evidence even when dropped ACKs
    /// leave the client's receipt base at zero.
    #[test]
    fn an_upload_whose_acks_never_reach_the_client_passes_the_shared_oracle() {
        scene(&PRINCIPALS, |mut scene| {
            let rules = vec![Rule::new(Selector::Kind(Kind::PutAck), Effect::Drop)];
            scene.nets[0].borrow_mut().set_rules(chain(rules, &[1]));
            let mut rec = Recorder::new(1);
            let mut tenures = tenures(&scene);
            let mut attempt =
                Attempt::begin(&mut scene, &mut rec, (6, Label(1)), LEN, &mut tenures);
            attempt.run(&mut scene, &mut rec, 3_000);
            assert_eq!(attempt.outcome, Some(UploadOutcome::Published));
            let dropped = selected(&scene, Kind::PutAck, |decision| decision.drop.is_some());
            assert!(dropped > 0, "the ACKs were dropped");
            let (_, base, _) = scene.clients[0]
                .put_receipt(attempt.id)
                .expect("the upload's receipt");
            assert_eq!(base, 0, "no ACK reached the client");
            let bytes: Vec<u8> = rec
                .rows()
                .iter()
                .filter(|r| r.kind == ActionKind::Receive)
                .flat_map(|r| r.payload.clone().expect("a fragment's bytes"))
                .collect();
            assert_eq!(
                bytes, attempt.object,
                "the receive rows carry what the owner validated"
            );
            get(&mut scene, &mut rec, 6, Label(1));
            passes(rec);
        });
    }

    #[test]
    fn a_live_cancelled_upload_over_an_incumbent_keeps_the_incumbent() {
        for turns_before_cancel in [0, 1] {
            scene(&PRINCIPALS, |mut scene| {
                let mut rec = Recorder::new(1);
                let mut tenures = tenures(&scene);
                let mut first =
                    Attempt::begin(&mut scene, &mut rec, (6, Label(1)), LEN, &mut tenures);
                first.run(&mut scene, &mut rec, 600);
                assert_eq!(first.outcome, Some(UploadOutcome::Published));
                let mut second =
                    Attempt::begin(&mut scene, &mut rec, (6, Label(2)), LEN, &mut tenures);
                assert!(second.supply(&mut scene, &mut rec, 0));
                for _ in 0..turns_before_cancel {
                    drive(&mut scene, 1);
                    second.observe(&scene, &mut rec);
                }
                second.cancel(&mut scene, &mut rec);
                for _ in 0..60 {
                    second.observe(&scene, &mut rec);
                    drive(&mut scene, 1);
                }
                second.observe(&scene, &mut rec);
                assert_eq!(
                    second.outcome,
                    Some(UploadOutcome::Failed(Status::Cancelled))
                );
                get(&mut scene, &mut rec, 6, Label(1));
                passes(rec);
            });
        }
    }

    /// The live history with the owner's publication removed claims
    /// `Published` on the strength of its full receipt and write completion,
    /// which the oracle rejects.
    #[test]
    fn a_live_upload_claimed_published_without_its_publication_fails_history() {
        scene(&PRINCIPALS, |mut scene| {
            let mut rec = Recorder::new(1);
            let mut tenures = tenures(&scene);
            let mut attempt =
                Attempt::begin(&mut scene, &mut rec, (6, Label(1)), LEN, &mut tenures);
            attempt.run(&mut scene, &mut rec, 600);
            let rows = rec.rows();
            let count = |kind: ActionKind, custodian: Custodian| {
                rows.iter()
                    .filter(|r| r.kind == kind && r.custodian == Some(custodian))
                    .count()
            };
            assert_eq!(count(ActionKind::Take, Custodian::Retransmission), 3);
            assert_eq!(count(ActionKind::Release, Custodian::Retransmission), 3);
            assert_eq!(
                count(ActionKind::Take, Custodian::Nic),
                count(ActionKind::Release, Custodian::Nic)
            );
            assert!(rows.iter().any(|r| r.kind == ActionKind::Ack));
            let claimed: Vec<_> = rows
                .iter()
                .filter(|r| r.kind != ActionKind::Publish)
                .cloned()
                .collect();
            assert_eq!(
                check(&Recorder::rebuilt(claimed)).violated(),
                Some((
                    Obligation::History,
                    "Published without the attempt's publication"
                ))
            );
        });
    }

    /// With the link holding each sent packet's device reference until its
    /// delayed delivery, the live history records NIC custody of the source
    /// slots and passes; another attempt's retake of a slot before its NIC
    /// return fails custody, and the same retake after it passes. The client frees a
    /// slot's piece only after its device return, so the live history ends
    /// a slot's retention no earlier than its NIC custody; the hand-written
    /// source histories hold the window where only the NIC holds a slot.
    ///
    /// The same holds when a delaying rule on PUT DATA, not a fault, keeps
    /// the references held, with the rule's delayed frames captured as the
    /// premise.
    #[test]
    fn a_live_source_slot_reused_under_nic_custody_fails_custody() {
        for by_rule in [false, true] {
            reused_under_nic_custody(by_rule);
        }
    }

    fn reused_under_nic_custody(by_rule: bool) {
        scene(&PRINCIPALS, |mut scene| {
            if by_rule {
                let delay = Rule::new(Selector::Kind(Kind::PutData), Effect::Delay(200));
                scene.nets[0]
                    .borrow_mut()
                    .set_rules(chain(vec![delay], &[1]));
            } else {
                let faults = Faults {
                    delay: 200,
                    ..Faults::default()
                };
                scene.nets[0].borrow_mut().set_faults(1, faults);
            }
            scene.nets[0]
                .borrow_mut()
                .set_tx_release(TxRelease::AtDelivery);
            let mut rec = Recorder::new(1);
            let mut tenures = tenures(&scene);
            let mut attempt =
                Attempt::begin(&mut scene, &mut rec, (6, Label(1)), LEN, &mut tenures);
            attempt.run(&mut scene, &mut rec, 3_000);
            assert_eq!(attempt.outcome, Some(UploadOutcome::Published));
            if by_rule {
                let delayed = selected(&scene, Kind::PutData, |decision| {
                    decision.delay == Some(200)
                });
                assert!(delayed > 0, "the rule delayed DATA, holding its references");
            }
            let other = rec.put_begin(KeyId(7), Label(2), 0, LEN);
            let serial = Serial::new(99).expect("a nonzero serial");
            rec.put_authority(other, KeyId(7), serial);
            rec.put_ready(other, (KeyId(7), Label(2)), (0, LEN), serial, 3);
            rec.put_result(
                other,
                (KeyId(7), Label(2)),
                Some(serial),
                PutOutcome::Failed(Status::Cancelled as u16),
            );
            let mut rows = rec.rows().to_vec();
            let failed = rows.pop().expect("the other attempt's result");
            let admitted: Vec<_> = rows.split_off(rows.len() - 3);
            let verdict = check(&Recorder::rebuilt(rows.clone()));
            assert!(
                verdict.satisfies(&[Obligation::Custody, Obligation::History]),
                "{verdict:?}"
            );
            let is = |r: &crate::oracle::Row, kind, custodian| {
                r.kind == kind && r.custodian == Some(custodian)
            };
            let taken = rows
                .iter()
                .position(|r| is(r, ActionKind::Take, Custodian::Nic))
                .expect("NIC custody of a source slot");
            let returned = rows
                .iter()
                .position(|r| {
                    is(r, ActionKind::Release, Custodian::Nic)
                        && r.resource() == rows[taken].resource()
                        && r.incarnation == rows[taken].incarnation
                })
                .expect("the slot's NIC return");
            let retaken = |at: usize| {
                let mut rows = rows.clone();
                let mut reuse = rows[taken].clone();
                reuse.op = other;
                reuse.custodian = Some(Custodian::Retransmission);
                reuse.incarnation = reuse.incarnation.map(|i| Incarnation(i.0 + 10));
                let mut inserted = admitted.clone();
                inserted.push(reuse);
                inserted.push(failed.clone());
                rows.splice(at..at, inserted);
                Recorder::renumber(&mut rows);
                check(&Recorder::rebuilt(rows))
            };
            assert_eq!(
                retaken(returned).violated(),
                Some((
                    Obligation::Custody,
                    "a resource was reused while a custodian held an earlier incarnation"
                ))
            );
            let after = rows
                .iter()
                .enumerate()
                .skip(returned)
                .find(|(_, r)| {
                    is(r, ActionKind::Release, Custodian::Retransmission)
                        && r.resource() == rows[taken].resource()
                        && r.incarnation == rows[taken].incarnation
                })
                .map(|(at, _)| at + 1)
                .unwrap_or(returned + 1);
            assert!(retaken(after).satisfies(&[Obligation::Custody]));
        });
    }

    /// The client frees a cancelled, device-held piece only after the
    /// device returns it, so the tenure's NIC return precedes its retention
    /// release.
    #[test]
    fn a_live_cancel_under_nic_custody_keeps_the_slot_until_the_device_returns() {
        scene(&PRINCIPALS, |mut scene| {
            let faults = Faults {
                delay: 200,
                ..Faults::default()
            };
            scene.nets[0].borrow_mut().set_faults(1, faults);
            scene.nets[0]
                .borrow_mut()
                .set_tx_release(TxRelease::AtDelivery);
            let mut rec = Recorder::new(1);
            let mut tenures = tenures(&scene);
            let mut attempt =
                Attempt::begin(&mut scene, &mut rec, (6, Label(1)), LEN, &mut tenures);
            for _ in 0..400 {
                if attempt.supply(&mut scene, &mut rec, 0) {
                    break;
                }
                drive(&mut scene, 1);
                attempt.observe(&scene, &mut rec);
            }
            for _ in 0..400 {
                drive(&mut scene, 1);
                attempt.observe(&scene, &mut rec);
                if attempt.slots.iter().flatten().any(|held| held.nic) {
                    break;
                }
            }
            assert!(
                attempt.slots.iter().flatten().any(|held| held.nic),
                "a sent fragment is device-held"
            );
            let device_held: Vec<(u32, u64)> = attempt
                .slots
                .iter()
                .enumerate()
                .filter_map(|(slot, held)| {
                    held.filter(|held| held.nic)
                        .map(|held| (slot as u32, held.tenure))
                })
                .collect();
            attempt.cancel(&mut scene, &mut rec);
            for _ in 0..3_000 {
                attempt.observe(&scene, &mut rec);
                if attempt.outcome.is_some() && attempt.slots.iter().all(Option::is_none) {
                    break;
                }
                drive(&mut scene, 1);
            }
            assert!(
                attempt.slots.iter().all(Option::is_none),
                "every slot returned"
            );
            assert_eq!(
                attempt.outcome,
                Some(UploadOutcome::Failed(Status::Cancelled))
            );
            let rows = rec.rows();
            for (slot, tenure) in device_held {
                let released = |custodian: Custodian| {
                    rows.iter()
                        .position(|r| {
                            r.kind == ActionKind::Release
                                && r.custodian == Some(custodian)
                                && r.resource().is_some_and(|res| res.index == slot)
                                && r.incarnation == Some(Incarnation(tenure))
                        })
                        .expect("the device-held tenure released")
                };
                assert!(
                    released(Custodian::Nic) < released(Custodian::Retransmission),
                    "slot {slot} tenure {tenure}: the NIC returned before retention ended"
                );
            }
            let verdict = check(&rec.finish());
            assert!(verdict.satisfies(&[Obligation::Custody]), "{verdict:?}");
        });
    }

    #[test]
    fn consecutive_live_uploads_under_nic_custody_pass_the_shared_oracle() {
        scene(&PRINCIPALS, |mut scene| {
            let faults = Faults {
                delay: 200,
                ..Faults::default()
            };
            scene.nets[0].borrow_mut().set_faults(1, faults);
            scene.nets[0]
                .borrow_mut()
                .set_tx_release(TxRelease::AtDelivery);
            let mut rec = Recorder::new(1);
            let mut tenures = tenures(&scene);
            let uploads = [(6, Label(1)), (7, Label(2))];
            for (name, label) in uploads {
                let mut attempt =
                    Attempt::begin(&mut scene, &mut rec, (name, label), LEN, &mut tenures);
                attempt.run(&mut scene, &mut rec, 3_000);
                assert_eq!(attempt.outcome, Some(UploadOutcome::Published));
            }
            let rows = rec.rows();
            assert!(
                rows.iter()
                    .any(|r| r.kind == ActionKind::Take && r.custodian == Some(Custodian::Nic)),
                "NIC custody of a source slot"
            );
            scene.nets[0].borrow_mut().set_faults(1, Faults::default());
            for (name, label) in uploads {
                get(&mut scene, &mut rec, name, label);
            }
            passes(rec);
        });
    }

    /// Every RESULT dropped after the owner published leaves the client's
    /// outcome `Unknown`, never an invented one, until the client abandons
    /// it; the dropped RESULTs and the full-receipt ACK are captured as the
    /// premise, the live history passes, and two controls fail through the
    /// oracle: the lost RESULT recorded as a failure, and publication
    /// claimed from the full receipt with the publication removed.
    #[test]
    fn a_result_lost_after_publication_stays_unknown_and_its_controls_fail() {
        scene(&PRINCIPALS, |mut scene| {
            let rules = vec![Rule::new(Selector::Kind(Kind::PutResult), Effect::Drop)];
            scene.nets[0].borrow_mut().set_rules(chain(rules, &[1]));
            let mut rec = Recorder::new(1);
            let mut tenures = tenures(&scene);
            let mut attempt =
                Attempt::begin(&mut scene, &mut rec, (6, Label(1)), LEN, &mut tenures);
            attempt.run(&mut scene, &mut rec, 20_000);
            assert!(scene.visible(6), "the owner published");
            assert_eq!(attempt.outcome, Some(UploadOutcome::Unknown));
            let dropped = selected(&scene, Kind::PutResult, |decision| decision.drop.is_some());
            assert!(dropped > 0, "the RESULTs were dropped");
            assert_eq!(
                scene.nets[0].borrow().audit().count(Reason::RuleDrop),
                dropped
            );
            let count = (LEN as usize).div_ceil(FRAGMENT) as u32;
            let full = committed(&scene)
                .iter()
                .any(|capture| capture.kind == Some(Kind::PutAck) && capture.index == Some(count));
            assert!(full, "the full-receipt ACK reached the client");
            assert!(scene.clients[0].abandon(attempt.id));
            get(&mut scene, &mut rec, 6, Label(1));
            let rows = rec.rows().to_vec();
            assert!(
                check(&Recorder::rebuilt(rows.clone())).satisfies(&[
                    Obligation::History,
                    Obligation::Bytes,
                    Obligation::Custody
                ]),
                "the live history passes"
            );
            let result = |row: &crate::oracle::Row| row.kind == ActionKind::PutResult;
            // The client's result row re-recorded with `outcome`.
            let recorded = |row: &mut crate::oracle::Row, outcome| {
                let mut scratch = Recorder::new(1);
                scratch.put_result(row.op, (KeyId(6), Label(1)), row.serial, outcome);
                let again = &scratch.rows()[0];
                row.outcome = again.outcome;
                row.open = again.open;
                row.label = again.label;
            };
            let mut failed = rows.clone();
            let row = failed
                .iter_mut()
                .find(|row| result(row))
                .expect("the client's result");
            recorded(row, PutOutcome::Failed(Status::OwnerUnavailable as u16));
            let verdict = check(&Recorder::rebuilt(failed));
            assert!(
                verdict.violated().is_some(),
                "a lost RESULT is not a failure: {verdict:?}"
            );
            let mut claimed: Vec<_> = rows
                .iter()
                .filter(|row| row.kind != ActionKind::Publish)
                .cloned()
                .collect();
            let row = claimed
                .iter_mut()
                .find(|row| result(row))
                .expect("the client's result");
            recorded(row, PutOutcome::Published);
            assert_eq!(
                check(&Recorder::rebuilt(claimed)).violated(),
                Some((
                    Obligation::History,
                    "Published without the attempt's publication"
                ))
            );
        });
    }

    /// A RESULT dropped once is answered again within the owner's retained
    /// result: the client publishes after the captured drop, and the GET
    /// reads its bytes.
    #[test]
    fn a_result_lost_once_is_answered_again_within_its_retained_scope() {
        scene(&PRINCIPALS, |mut scene| {
            let rules = vec![Rule::new(Selector::Kind(Kind::PutResult), Effect::Drop).window(0, 1)];
            scene.nets[0].borrow_mut().set_rules(chain(rules, &[1]));
            let mut rec = Recorder::new(1);
            let mut tenures = tenures(&scene);
            let mut attempt =
                Attempt::begin(&mut scene, &mut rec, (6, Label(1)), LEN, &mut tenures);
            attempt.run(&mut scene, &mut rec, 6_000);
            assert_eq!(attempt.outcome, Some(UploadOutcome::Published));
            assert_eq!(
                selected(&scene, Kind::PutResult, |decision| decision.drop.is_some()),
                1
            );
            assert!(selected(&scene, Kind::PutResult, |decision| decision.drop.is_none()) > 0);
            get(&mut scene, &mut rec, 6, Label(1));
            passes(rec);
        });
    }

    /// Rules that duplicate and reorder DATA and open a hole by dropping
    /// fragment 1 once: the hole shows in a receipt mask, the attempt
    /// publishes once and the GET reads its bytes, and the receipt base
    /// never passes the fragment count, so duplicates added no credit. The
    /// same rules replay the same selected frames, ranges and taps. Two
    /// validations of one fragment, the duplicate-credit control, fail the
    /// oracle.
    #[test]
    fn duplicated_reordered_and_missing_fragments_add_no_credit() {
        let run = |chooser: Chooser| {
            let draws: Draws = Rc::new(RefCell::new(chooser));
            let mut captured = Vec::new();
            drawn_scene(&draws, |mut scene| {
                let data = Selector::Kind(Kind::PutData);
                let rules = vec![
                    Rule::new(data.clone(), Effect::Duplicate).window(0, 2),
                    Rule::new(data.clone(), Effect::Reorder).window(2, 1),
                    Rule::new(
                        Selector::All(vec![data, Selector::Fragments { first: 1, last: 1 }]),
                        Effect::Drop,
                    )
                    .window(0, 1),
                    Rule::new(Selector::Holes, Effect::Delay(0)),
                ];
                scene.nets[0].borrow_mut().set_rules(chain(rules, &[4]));
                let mut rec = Recorder::new(1);
                let mut tenures = tenures(&scene);
                let mut attempt =
                    Attempt::begin(&mut scene, &mut rec, (6, Label(1)), LEN, &mut tenures);
                attempt.run(&mut scene, &mut rec, 6_000);
                assert_eq!(attempt.outcome, Some(UploadOutcome::Published));
                let duplicated = selected(&scene, Kind::PutData, |decision| decision.duplicate);
                assert_eq!(duplicated, 2);
                let holes = selected(&scene, Kind::PutAck, |decision| decision.delay == Some(0));
                assert!(holes > 0, "a receipt mask named a fragment past the hole");
                let seen = committed(&scene);
                let is_data = |c: &&Capture, dropped: bool| {
                    c.kind == Some(Kind::PutData)
                        && c.index == Some(1)
                        && c.decision.drop.is_some() == dropped
                };
                let hole = seen
                    .iter()
                    .find(|c| is_data(c, true))
                    .expect("fragment 1 dropped");
                let filled = seen
                    .iter()
                    .find(|c| is_data(c, false) && c.ordinal > hole.ordinal)
                    .expect("fragment 1 resent after the hole");
                let early = seen.iter().any(|c| {
                    c.kind == Some(Kind::PutAck)
                        && c.index.is_some_and(|base| base > 1)
                        && c.ordinal < filled.ordinal
                });
                assert!(
                    !early,
                    "no receipt credited past the hole before fragment 1 arrived"
                );
                get(&mut scene, &mut rec, 6, Label(1));
                let rows = rec.rows().to_vec();
                passes(rec);
                let ready = rows
                    .iter()
                    .find(|row| row.kind == ActionKind::Ready)
                    .expect("READY")
                    .clone();
                let mut credited = rows;
                for _ in 0..2 {
                    let mut fragment = ready.clone();
                    fragment.kind = ActionKind::Fragment;
                    fragment.fragment = Some(0);
                    fragment.label = None;
                    fragment.grant = None;
                    fragment.payload = Some(attempt.object[..FRAGMENT].to_vec());
                    credited.push(fragment);
                }
                Recorder::renumber(&mut credited);
                assert_eq!(
                    check(&Recorder::rebuilt(credited)).violated(),
                    Some((
                        Obligation::History,
                        "an attempt validated one fragment twice"
                    ))
                );
                captured = committed(&scene);
            });
            let draws = Rc::try_unwrap(draws).expect("the scene released the chooser");
            (
                captured,
                draws.into_inner().finish().expect("a well-formed tape"),
            )
        };
        let (first, tape) = run(Chooser::record(9, &drawn_sites()));
        let (replayed, _) = run(Chooser::replay(&drawn_sites(), tape));
        assert_eq!(
            replayed, first,
            "the tape replays the same selected frames and taps"
        );
    }

    /// A PUT body corrupted on its way to the owner is rejected by
    /// authentication, the layer its class names, since the tag covers a
    /// PUT body; the attempt resends and publishes.
    #[test]
    fn a_corrupted_put_body_is_rejected_by_authentication() {
        use super::super::datagram::PeerId;
        use super::super::frame::Direction;
        use super::super::rules::{Corruption, contain};
        scene(&PRINCIPALS, |mut scene| {
            let corrupt = Effect::Corrupt(Corruption::PutBody);
            let rules = vec![Rule::new(Selector::Kind(Kind::PutData), corrupt).window(0, 1)];
            scene.nets[0].borrow_mut().set_rules(chain(rules, &[]));
            let mut rec = Recorder::new(1);
            let mut tenures = tenures(&scene);
            let mut attempt =
                Attempt::begin(&mut scene, &mut rec, (6, Label(1)), LEN, &mut tenures);
            attempt.run(&mut scene, &mut rec, 6_000);
            assert_eq!(attempt.outcome, Some(UploadOutcome::Published));
            let net = scene.nets[0].borrow();
            let receiver = |_| {
                let endpoint = super::super::owner_tests::ENDPOINT;
                (
                    &scene.rings[0],
                    PeerId(0),
                    endpoint,
                    Direction::ClientToOwner,
                )
            };
            assert_eq!(contain(net.damaged(), receiver), Ok(1));
        });
    }

    /// One upload of a three-fragment object under key 6, over a link whose only rule applies an effect to
    /// every PUT RESULT, judged at the client's first decision and again 300 turns later. With every RESULT
    /// dropped and the full-receipt ACK delivered, the upload is `Unknown`, not `Published`, which only a
    /// RESULT can say, and not `Failed`, which would report an object the owner binds as a failure: under a
    /// 30 s deadline it is decided before the deadline, and under a 30 ms deadline on the first turn at or
    /// after the deadline. The control delivers every RESULT through the same rule and ends `Published`, so
    /// the lost RESULT is what the two cases turn on.
    #[test]
    fn every_result_lost_is_unknown_at_the_decision_and_a_delivered_result_publishes() {
        for (effect, wait_us, outcome, at) in [
            (
                Effect::Drop,
                30_000_000,
                UploadOutcome::Unknown,
                "dropped, 30 s",
            ),
            (
                Effect::Drop,
                30_000,
                UploadOutcome::Unknown,
                "dropped, 30 ms",
            ),
            (
                Effect::Deliver,
                30_000_000,
                UploadOutcome::Published,
                "delivered",
            ),
        ] {
            scene(&PRINCIPALS, |mut scene| {
                let rules = vec![Rule::new(Selector::Kind(Kind::PutResult), effect)];
                scene.nets[0].borrow_mut().set_rules(chain(rules, &[1]));
                let object = payload(LEN as usize, 40);
                let deadline_us = scene.turn * 100 + wait_us;
                let id = upload(&mut scene, 6, &object, wait_us);
                supply_all(&mut scene, id, &object, 40_000);
                // `supply_all` returns after the turn that decided the upload, which began one turn earlier.
                let decided_us = (scene.turn - 1) * 100;
                assert_eq!(scene.clients[0].put_outcome(id), Some(outcome), "{at}");
                assert!(
                    scene.nets[0].borrow().rules().overflow().is_none(),
                    "{at}: the link kept every capture"
                );
                let dropped = selected(&scene, Kind::PutResult, |decision| decision.drop.is_some());
                let delivered =
                    selected(&scene, Kind::PutResult, |decision| decision.drop.is_none());
                assert_eq!(
                    scene.nets[0].borrow().audit().count(Reason::RuleDrop),
                    dropped,
                    "{at}: the rule dropped RESULTs alone"
                );
                let count = (LEN as usize).div_ceil(FRAGMENT) as u32;
                let full = committed(&scene).iter().any(|capture| {
                    capture.kind == Some(Kind::PutAck)
                        && capture.index == Some(count)
                        && capture.decision.drop.is_none()
                });
                assert!(full, "{at}: the full-receipt ACK reached the client");
                if outcome == UploadOutcome::Published {
                    assert!(dropped == 0 && delivered > 0, "{at}: {dropped} {delivered}");
                } else {
                    assert!(dropped > 0 && delivered == 0, "{at}: {dropped} {delivered}");
                    if wait_us == 30_000 {
                        assert!(
                            (deadline_us..deadline_us + 100).contains(&decided_us),
                            "{at}: decided at {decided_us}, the first turn at or after {deadline_us}"
                        );
                    } else {
                        assert!(
                            decided_us < deadline_us,
                            "{at}: the resends ran out before the deadline"
                        );
                    }
                }
                drive(&mut scene, 300);
                assert_eq!(
                    scene.clients[0].put_outcome(id),
                    Some(outcome),
                    "{at}: 300 turns later"
                );
                assert!(scene.visible(6), "{at}: the owner published");
            });
        }
    }

    /// A RESULT lost until the client's deadline leaves the attempt
    /// `Unknown`: the client stops resending at its deadline, which the
    /// owner's retained result outlasts by its linger, so no resend meets an
    /// expired row. After the first publication is invalidated, a matching
    /// retry in the same session publishes as its own attempt while the
    /// first stays `Unknown` until abandoned, and the history passes.
    #[test]
    fn a_retry_after_a_lost_result_leaves_the_first_attempt_unknown() {
        scene(&PRINCIPALS, |mut scene| {
            let rules = vec![Rule::new(Selector::Kind(Kind::PutResult), Effect::Drop)];
            scene.nets[0].borrow_mut().set_rules(chain(rules, &[1]));
            let mut rec = Recorder::new(1);
            let mut tenures = tenures(&scene);
            let mut first = Attempt::begin_waiting(
                &mut scene,
                &mut rec,
                (6, Label(1)),
                LEN,
                &mut tenures,
                20_000,
            );
            first.run(&mut scene, &mut rec, 3_000);
            assert_eq!(first.outcome, Some(UploadOutcome::Unknown));
            assert!(scene.visible(6), "the owner published");
            let first = first.id;
            scene.nets[0].borrow_mut().set_rules(Chain::default());
            // The retry's publication must be observable apart from the first's.
            let budget = &mut crate::storage::WorkBudget::new(1 << 12);
            assert!(
                scene
                    .owner
                    .invalidate(&super::super::owner_tests::key(6), 3, budget)
                    .is_ok()
            );
            rec.invalidate(KeyId(6), Outcome::Acknowledged);
            let session = scene.clients[0].session_epoch();
            let mut retry = Attempt::begin(&mut scene, &mut rec, (6, Label(2)), LEN, &mut tenures);
            retry.run(&mut scene, &mut rec, 6_000);
            assert_eq!(retry.outcome, Some(UploadOutcome::Published));
            assert_eq!(scene.clients[0].session_epoch(), session, "one session");
            // Past the first attempt's deadline and the owner's linger, its retained row is gone.
            let linger = super::super::owner_tests::OWNER.serve.linger_us;
            scene.turns((20_000 + linger) / 100 + 1);
            assert_eq!(
                scene.clients[0].put_outcome(first),
                Some(UploadOutcome::Unknown)
            );
            assert!(scene.clients[0].abandon(first));
            get(&mut scene, &mut rec, 6, Label(2));
            passes(rec);
        });
    }

    /// PUT control traffic is selected by kind and session: a rule delays
    /// every PREPARE, another drops the first READY of the client's session,
    /// and the cancel the client then sends is captured. The attempt still
    /// becomes ready, ends cancelled with nothing published, and the history
    /// passes.
    #[test]
    fn put_control_traffic_is_selected_by_kind_and_session() {
        scene(&PRINCIPALS, |mut scene| {
            let session = scene.clients[0].session_epoch().expect("an active session");
            let ready = Selector::All(vec![
                Selector::Kind(Kind::PutReady),
                Selector::Session(session),
            ]);
            let rules = vec![
                Rule::new(Selector::Kind(Kind::PutPrepare), Effect::Delay(3)),
                Rule::new(ready, Effect::Drop).window(0, 1),
                Rule::new(Selector::Kind(Kind::PutCancel), Effect::Prompt),
            ];
            scene.nets[0].borrow_mut().set_rules(chain(rules, &[3]));
            let mut rec = Recorder::new(1);
            let mut tenures = tenures(&scene);
            let mut attempt =
                Attempt::begin(&mut scene, &mut rec, (6, Label(1)), LEN, &mut tenures);
            for _ in 0..600 {
                if attempt.ready {
                    break;
                }
                drive(&mut scene, 1);
                attempt.observe(&scene, &mut rec);
            }
            assert!(attempt.ready, "a later READY arrived");
            attempt.cancel(&mut scene, &mut rec);
            for _ in 0..200 {
                drive(&mut scene, 1);
                attempt.observe(&scene, &mut rec);
            }
            assert_eq!(
                attempt.outcome,
                Some(UploadOutcome::Failed(Status::Cancelled))
            );
            let delayed = selected(&scene, Kind::PutPrepare, |decision| {
                decision.delay == Some(3)
            });
            assert!(delayed > 0, "PREPARE was delayed");
            assert_eq!(
                selected(&scene, Kind::PutReady, |decision| decision.drop.is_some()),
                1
            );
            assert!(selected(&scene, Kind::PutReady, |decision| decision.drop.is_none()) > 0);
            assert!(
                selected(&scene, Kind::PutCancel, |decision| decision.delay
                    == Some(0))
                    > 0
            );
            assert!(!scene.visible(6), "a cancelled attempt publishes nothing");
            get(&mut scene, &mut rec, 6, Label(1));
            let verdict = check(&rec.finish());
            assert!(verdict.satisfies(&[Obligation::History]), "{verdict:?}");
        });
    }

    crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
        a_live_cancel_under_nic_custody_keeps_the_slot_until_the_device_returns,
        a_live_cancelled_upload_over_an_incumbent_keeps_the_incumbent,
        a_live_upload_claimed_published_without_its_publication_fails_history,
        a_live_upload_over_a_lossy_link_passes_the_shared_oracle,
        a_live_upload_then_get_passes_the_shared_oracle,
        a_result_lost_after_publication_stays_unknown_and_its_controls_fail,
        a_result_lost_once_is_answered_again_within_its_retained_scope,
        a_retry_after_a_lost_result_leaves_the_first_attempt_unknown,
        duplicated_reordered_and_missing_fragments_add_no_credit,
        put_control_traffic_is_selected_by_kind_and_session,
    );
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    a_begin_in_a_refused_send_call_is_unknown,
    a_begin_never_handed_to_send_has_not_started,
    a_cancel_after_a_send_ends_through_the_owner,
    a_cancel_keeps_a_device_held_source_and_its_bytes_until_the_device_returns_them,
    a_data_frame_past_the_send_sequence_counts_as_dropped,
    a_delayed_result_resolves_a_retained_unknown_and_is_inert_after_retire,
    a_device_return_before_the_receipt_keeps_the_slot,
    a_full_receipt_with_its_final_write_held_publishes_only_after_the_release,
    a_lost_zero_byte_result_resolves_on_the_prepare_retry,
    a_receipt_mask_bit_keeps_its_slot_until_the_base_passes,
    a_refused_permission_starts_no_source_work,
    a_replaced_uploads_device_held_source_outlives_the_replacement_and_its_successor,
    a_session_replacement_after_a_send_is_unknown_until_abandoned,
    a_short_write_cancel_and_invalidation_leave_their_keys_absent,
    a_silent_owner_after_a_possible_send_is_unknown,
    a_slot_frees_only_after_both_its_receipt_and_its_device_return,
    a_slot_stays_held_until_its_device_reference_ends,
    a_supplied_fragment_wakes_the_client_at_once,
    a_zero_byte_upload_publishes_after_its_header_write,
    an_owner_close_during_writes_ends_the_upload_unknown_and_frees_its_slots,
    an_upload_beyond_the_peer_share_fails_typed,
    an_upload_streams_its_fragments_and_publishes_the_exact_bytes,
    closed_sources_keep_the_arena_until_the_device_returns_them,
    early_slot_reuse_fails_the_oracle,
    input_waits_for_authority_and_ready,
    lost_data_and_a_lost_result_recover_with_the_same_bytes,
    metadata_across_fragments_and_a_multi_command_body_reach_the_oracle,
    puts_beyond_the_request_slots_are_refused,
    refused_lost_and_reordered_sends_still_publish_the_exact_bytes,
    steady_state_upload_calls_allocate_nothing,
);

/// An upload core over `requests`' table that resends every `retry_us`, at most `attempts` times.
fn limited_core<'a>(
    requests: &mut ClientRequests<'a>,
    retry_us: u64,
    attempts: u32,
) -> UploadCore<'a> {
    let config = UploadConfig { retry_us, attempts };
    UploadCore::new(
        config,
        Box::default(),
        requests,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap()
}

/// A live upload's timer, its deadline while its BEGIN is due, is reported at its value, 0 and `u64::MAX` included, and the tick at the deadline decides the upload while the tick before it leaves it live.
#[test]
fn a_put_timer_is_present_at_every_timestamp_and_expires_at_its_deadline() {
    for (member, now, wait, deadline) in [
        ("put-timer-zero-live", 0, 0, 0),
        ("put-timer-max-live", 0, u64::MAX, u64::MAX),
        ("put-timer-saturating-live", u64::MAX - 5, 100, u64::MAX),
        ("put-inclusive-expiry", 0, 10_000, 10_000),
    ] {
        let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
        let mut budget = EngineBudget::new(1 << 20);
        let mut requests =
            ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
        let mut core = limited_core(&mut requests, 1_000, 3);
        let id = core
            .put(&mut requests, SESSION, key(6), CacheVersion(0), now, wait)
            .unwrap();
        assert_eq!(core.wake(&requests), (true, Some(deadline)), "{member}");
        if deadline > now {
            core.tick(&mut requests, deadline - 1);
            assert_eq!(
                core.outcome(&requests, id),
                None,
                "{member}: live before the deadline"
            );
        }
        core.tick(&mut requests, deadline);
        assert_eq!(
            core.outcome(&requests, id),
            Some(UploadOutcome::NotStarted),
            "{member}: the deadline's tick decides it"
        );
        assert_eq!(
            core.wake(&requests).1,
            None,
            "{member}: a decided upload has no timer"
        );
    }
}

/// PUT counts its staged control sends, the first included, and ends once the count exceeds the limit. At limit 0 the first retry timer after the BEGIN decides the upload with no resend; at `u32::MAX`, a count seeded at the limit resends once, its count passing `u32::MAX` without wrapping, and the next retry timer decides it.
#[test]
fn put_resends_hold_at_zero_and_at_the_largest_limit() {
    for (member, attempts, seed) in [
        ("put-retry-zero", 0, None),
        ("put-retry-max", u32::MAX, Some(u64::from(u32::MAX))),
    ] {
        let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
        let mut budget = EngineBudget::new(1 << 20);
        let mut requests =
            ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
        let mut core = limited_core(&mut requests, 1_000, attempts);
        let id = core
            .put(&mut requests, SESSION, key(6), CacheVersion(0), 0, u64::MAX)
            .unwrap();
        assert_eq!(
            sent(&mut core, &mut requests, 0),
            [Kind::PutBegin],
            "{member}"
        );
        let mut now = 1_000;
        if let Some(seed) = seed {
            UploadCore::seed_sends(&mut requests, id, seed);
            core.tick(&mut requests, now);
            assert_eq!(
                sent(&mut core, &mut requests, now),
                [Kind::PutBegin],
                "{member}: the last resend"
            );
            assert_eq!(UploadCore::sends(&requests, id), Some(seed + 1));
            now += 1_000;
        }
        core.tick(&mut requests, now);
        assert!(
            sent(&mut core, &mut requests, now).is_empty(),
            "{member}: no further send"
        );
        assert_eq!(
            core.outcome(&requests, id),
            Some(UploadOutcome::NotStarted),
            "{member}: the resends ran out"
        );
    }
}

/// A staged control frame the transport leaves untaken returns its send to the count and is due again, and a READY, an ACK, an ACK of every fragment and a cancel each restart the count.
#[test]
fn an_untaken_put_send_returns_its_count_and_a_reply_resets_it() {
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut budget = EngineBudget::new(1 << 20);
    let mut requests =
        ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let mut core = limited_core(&mut requests, 1_000, 5);
    let id = core
        .put(&mut requests, SESSION, key(6), CacheVersion(0), 0, u64::MAX)
        .unwrap();
    let wire = requests.upload(id).unwrap().wire();
    assert_eq!(sent(&mut core, &mut requests, 0), [Kind::PutBegin]);
    core.handed(&mut requests, (PeerId(0), wire), true, true);
    core.tick(&mut requests, 1_000);
    assert_eq!(sent(&mut core, &mut requests, 1_000), [Kind::PutBegin]);
    assert_eq!(UploadCore::sends(&requests, id), Some(2));
    core.handed(&mut requests, (PeerId(0), wire), true, false);
    assert_eq!(
        UploadCore::sends(&requests, id),
        Some(1),
        "put-retry-untaken-refund: the untaken resend returns its one send"
    );
    assert_eq!(
        sent(&mut core, &mut requests, 1_000),
        [Kind::PutBegin],
        "and is due again"
    );
    core.handed(&mut requests, (PeerId(0), wire), true, true);
    let authority = reply(id, &requests, Kind::PutAuthority, |_| {});
    assert!(core.receive(&mut requests, SESSION, &authority, 10));
    core.prepare(&mut requests, id, 0, 2 * 8192, TTL_MS)
        .unwrap();
    assert_eq!(sent(&mut core, &mut requests, 20), [Kind::PutPrepare]);
    core.tick(&mut requests, 1_020);
    assert_eq!(sent(&mut core, &mut requests, 1_020), [Kind::PutPrepare]);
    assert_eq!(UploadCore::sends(&requests, id), Some(2));
    let ready = reply(id, &requests, Kind::PutReady, |reply| reply.grant = 2);
    assert!(core.receive(&mut requests, SESSION, &ready, 1_030));
    assert_eq!(
        UploadCore::sends(&requests, id),
        Some(0),
        "put-retry-reply-reset: READY restarts the count"
    );
    let mut now = 1_030;
    for (event, index) in [("ACK", 1), ("ACK of every fragment", 2)] {
        now += 1_001;
        core.tick(&mut requests, now);
        assert_eq!(
            sent(&mut core, &mut requests, now),
            [Kind::PutPrepare],
            "{event}"
        );
        assert_eq!(UploadCore::sends(&requests, id), Some(1), "{event}");
        let ack = reply(id, &requests, Kind::PutAck, |reply| {
            reply.index = index;
            reply.grant = 2;
        });
        assert!(core.receive(&mut requests, SESSION, &ack, now));
        assert_eq!(
            UploadCore::sends(&requests, id),
            Some(0),
            "put-retry-reply-reset: an {event} restarts the count"
        );
    }
    now += 1_001;
    core.tick(&mut requests, now);
    assert_eq!(sent(&mut core, &mut requests, now), [Kind::PutPrepare]);
    core.cancel(&mut requests, id);
    assert_eq!(
        UploadCore::sends(&requests, id),
        Some(0),
        "put-retry-reply-reset: a cancel restarts the count for its PUT CANCEL"
    );
}

#[test]
fn the_clients_own_uploads_fill_its_slots_and_refuse_its_get_locally_until_one_retires() {
    own_uploads_fill_the_slots(OwnUploads::AsStated);
}

/// The control for the local refusal: between the first refused GET and the admission state read after it, a
/// decided upload retires and a GET takes its slot, so the census is as before and the wire generation one ahead,
/// the state a refused admission leaves when it draws its generation before its checks.
#[test]
#[should_panic(expected = "a refused GET leaves the census and the wire generation")]
fn negative_control_a_get_admitted_beside_a_refused_get_advances_the_generation() {
    own_uploads_fill_the_slots(OwnUploads::AdmittedBesideTheRefusal);
}

/// The control for the recovery: the decided upload is not retired, so it keeps its slot and the GET after it is
/// refused, as when closing a decided upload keeps its request record.
#[test]
#[should_panic(expected = "the retired upload's slot admits the GET")]
fn negative_control_an_unretired_upload_keeps_its_slot_and_refuses_the_get() {
    own_uploads_fill_the_slots(OwnUploads::Unretired);
}

/// What a run of [`own_uploads_fill_the_slots`] changes in its sequence.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OwnUploads {
    /// The sequence as the test states it.
    AsStated,
    /// A decided upload retires and a GET takes its slot between the first refused GET and the read after it.
    AdmittedBesideTheRefusal,
    /// The decided upload stays unretired before the GET that its slot should admit.
    Unretired,
}

/// Cancels client 0's upload `id` and drives the scene until the upload has an outcome.
fn decide(scene: &mut Scene<'_, '_>, id: RequestId) {
    scene.clients[0].cancel(id);
    for _ in 0..200 {
        if scene.clients[0].put_outcome(id).is_some() {
            break;
        }
        drive(scene, 1);
    }
    assert!(
        scene.clients[0].put_outcome(id).is_some(),
        "the cancelled upload decided"
    );
}

/// Fills client 0's request slots with its own uploads, checks that three GETs are refused locally with the
/// census and the wire generation unchanged, then retires one decided upload and checks that its slot admits the
/// next GET with the generation advanced by one.
fn own_uploads_fill_the_slots(plant: OwnUploads) {
    scene(&PRINCIPALS, |mut scene| {
        let probe = RequestId::from_wire(request(0, 0));
        drive(&mut scene, 200);
        assert!(
            scene.clients[0].outcome(probe).is_some(),
            "the scene's GET decided"
        );
        assert!(scene.clients[0].retire(probe));
        let (census, _) = scene.clients[0].admission_state();
        assert_eq!(census.live(), 0);
        let now = scene.turn * 100;
        let mut uploads = Vec::new();
        while let Ok(id) = scene.clients[0].put(key(6), CacheVersion(0), now, 30_000_000) {
            uploads.push(id);
        }
        drive(&mut scene, 6);
        let (census, _) = scene.clients[0].admission_state();
        let cap = super::owner_tests::client_config(0).caps.slots;
        assert_eq!(census.live(), cap, "the uploads hold every slot");
        assert_eq!(scene.clients[0].live_uploads(), cap as usize);
        let beside = plant == OwnUploads::AdmittedBesideTheRefusal;
        if beside {
            decide(&mut scene, uploads[1]);
        }
        for round in 0..3 {
            let before = scene.clients[0].admission_state();
            let now = scene.turn * 100;
            assert_eq!(
                scene.clients[0].get(key(1), 0, 1 << 20, now, 30_000_000),
                Err(GetRefused::RequestPressure)
            );
            if beside && round == 0 {
                assert!(
                    scene.clients[0].retire(uploads[1]),
                    "the decided upload retires"
                );
                assert!(
                    scene.clients[0]
                        .get(key(1), 0, 1 << 20, now, 30_000_000)
                        .is_ok(),
                    "the freed slot admits the GET"
                );
                assert_eq!(
                    scene.clients[0].admission_state().0,
                    before.0,
                    "the retirement and the admitted GET leave the census as it was"
                );
            }
            assert_eq!(
                scene.clients[0].admission_state(),
                before,
                "a refused GET leaves the census and the wire generation"
            );
            let report = scene.clients[0].poll(now);
            assert_eq!(report.sent, 0, "the refused GET sends nothing");
            assert_eq!(
                scene.nets[0].borrow().pending(1),
                0,
                "the transport queue toward the owner is empty"
            );
        }
        assert_eq!(scene.clients[0].refusals().request_pressure, 3);
        let retiring = uploads[0];
        decide(&mut scene, retiring);
        let (before, next) = scene.clients[0].admission_state();
        if plant != OwnUploads::Unretired {
            assert!(scene.clients[0].retire(retiring));
        }
        let now = scene.turn * 100;
        let admitted = scene.clients[0].get(key(1), 0, 1 << 20, now, 30_000_000);
        assert!(admitted.is_ok(), "the retired upload's slot admits the GET");
        let (after, issued) = scene.clients[0].admission_state();
        assert_eq!(after.live(), before.live());
        assert_eq!(issued, next.map(|next| next + 1));
    });
}

/// A cancelled upload refuses further input, so a `prepare` after the cancel leaves its PUT CANCEL's resend count as it was, and a silent owner ends the upload `Unknown` after the first CANCEL and `attempts` resends.
#[test]
fn a_prepare_after_a_cancel_is_refused_and_keeps_the_cancel_budget() {
    for prepare_after in [None, Some(2)] {
        let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
        let mut budget = EngineBudget::new(1 << 20);
        let mut requests =
            ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
        let mut core = limited_core(&mut requests, 1_000, 3);
        let id = core
            .put(&mut requests, SESSION, key(6), CacheVersion(0), 0, u64::MAX)
            .unwrap();
        let wire = requests.upload(id).unwrap().wire();
        assert_eq!(sent(&mut core, &mut requests, 0), [Kind::PutBegin]);
        core.handed(&mut requests, (PeerId(0), wire), true, true);
        let authority = reply(id, &requests, Kind::PutAuthority, |_| {});
        assert!(core.receive(&mut requests, SESSION, &authority, 10));
        core.cancel(&mut requests, id);
        let mut cancels = 0;
        let mut now = 10;
        while core.outcome(&requests, id).is_none() && cancels < 20 {
            let kinds = sent(&mut core, &mut requests, now);
            assert!(
                kinds.iter().all(|&kind| kind == Kind::PutCancel),
                "{kinds:?}"
            );
            cancels += kinds.len();
            if prepare_after == Some(cancels) {
                assert_eq!(
                    core.prepare(&mut requests, id, 0, 8192, TTL_MS),
                    Err(PrepareRefused::Phase),
                    "a cancelled upload refuses further input"
                );
            }
            now += 1_001;
            core.tick(&mut requests, now);
        }
        assert_eq!(
            (cancels, core.outcome(&requests, id)),
            (4, Some(UploadOutcome::Unknown)),
            "prepare after {prepare_after:?} CANCEL sends"
        );
    }
}

/// `attempts` bounds a silent owner's PUT CANCEL resends whatever the caller does after the cancel: a second `cancel` of the cancelled upload after its second CANCEL leaves the resend count as it was, so the upload ends `Unknown` after the first CANCEL and `attempts` resends.
#[test]
fn a_repeated_cancel_leaves_the_cancel_resend_count() {
    let mut counts = Vec::new();
    for cancel_after in [None, Some(2)] {
        let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
        let mut budget = EngineBudget::new(1 << 20);
        let mut requests =
            ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
        let mut core = limited_core(&mut requests, 1_000, 3);
        let id = core
            .put(&mut requests, SESSION, key(6), CacheVersion(0), 0, u64::MAX)
            .unwrap();
        let wire = requests.upload(id).unwrap().wire();
        assert_eq!(sent(&mut core, &mut requests, 0), [Kind::PutBegin]);
        core.handed(&mut requests, (PeerId(0), wire), true, true);
        let authority = reply(id, &requests, Kind::PutAuthority, |_| {});
        assert!(core.receive(&mut requests, SESSION, &authority, 10));
        core.cancel(&mut requests, id);
        let mut cancels = 0;
        let mut now = 10;
        while core.outcome(&requests, id).is_none() && cancels < 20 {
            let kinds = sent(&mut core, &mut requests, now);
            assert!(
                kinds.iter().all(|&kind| kind == Kind::PutCancel),
                "{kinds:?}"
            );
            cancels += kinds.len();
            if cancel_after == Some(cancels) {
                core.cancel(&mut requests, id);
            }
            now += 1_001;
            core.tick(&mut requests, now);
        }
        counts.push((cancels, core.outcome(&requests, id)));
    }
    assert_eq!(
        counts,
        [
            (4, Some(UploadOutcome::Unknown)),
            (4, Some(UploadOutcome::Unknown))
        ],
        "without and with a second cancel after the second CANCEL"
    );
}

/// A sent PUT CANCEL waits `retry_us` for its reply before the next resend whatever the caller does after the cancel: a second `cancel` of the cancelled upload inside that interval queues no further CANCEL.
#[test]
fn a_repeated_cancel_sends_no_cancel_before_the_retry_interval() {
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut budget = EngineBudget::new(1 << 20);
    let mut requests =
        ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let mut core = limited_core(&mut requests, 1_000, 3);
    let id = core
        .put(&mut requests, SESSION, key(6), CacheVersion(0), 0, u64::MAX)
        .unwrap();
    let wire = requests.upload(id).unwrap().wire();
    assert_eq!(sent(&mut core, &mut requests, 0), [Kind::PutBegin]);
    core.handed(&mut requests, (PeerId(0), wire), true, true);
    let authority = reply(id, &requests, Kind::PutAuthority, |_| {});
    assert!(core.receive(&mut requests, SESSION, &authority, 10));
    core.cancel(&mut requests, id);
    assert_eq!(sent(&mut core, &mut requests, 10), [Kind::PutCancel]);
    let before = UploadCore::sends(&requests, id);
    core.cancel(&mut requests, id);
    assert_eq!(
        sent(&mut core, &mut requests, 11),
        Vec::<Kind>::new(),
        "the first CANCEL was sent 1 us ago and waits 1000 us for its reply"
    );
    assert_eq!(UploadCore::sends(&requests, id), before);
}

/// `attempts` bounds a silent owner's PUT CANCEL resends whatever the caller does after the cancel: with or without a `prepare` after the second CANCEL, whose result is not judged here, the upload ends `Unknown` after the first CANCEL and `attempts` resends.
#[test]
fn a_prepare_after_a_cancel_leaves_the_cancel_resend_count() {
    let mut counts = Vec::new();
    for prepare_after in [None, Some(2)] {
        let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
        let mut budget = EngineBudget::new(1 << 20);
        let mut requests =
            ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
        let mut core = limited_core(&mut requests, 1_000, 3);
        let id = core
            .put(&mut requests, SESSION, key(6), CacheVersion(0), 0, u64::MAX)
            .unwrap();
        let wire = requests.upload(id).unwrap().wire();
        assert_eq!(sent(&mut core, &mut requests, 0), [Kind::PutBegin]);
        core.handed(&mut requests, (PeerId(0), wire), true, true);
        let authority = reply(id, &requests, Kind::PutAuthority, |_| {});
        assert!(core.receive(&mut requests, SESSION, &authority, 10));
        core.cancel(&mut requests, id);
        let mut cancels = 0;
        let mut now = 10;
        while core.outcome(&requests, id).is_none() && cancels < 20 {
            let kinds = sent(&mut core, &mut requests, now);
            assert!(
                kinds.iter().all(|&kind| kind == Kind::PutCancel),
                "{kinds:?}"
            );
            cancels += kinds.len();
            if prepare_after == Some(cancels) {
                let _ = core.prepare(&mut requests, id, 0, 8192, TTL_MS);
            }
            now += 1_001;
            core.tick(&mut requests, now);
        }
        counts.push((cancels, core.outcome(&requests, id)));
    }
    assert_eq!(
        counts,
        [(4, Some(UploadOutcome::Unknown)); 2],
        "PUT CANCEL sends without and with a prepare after the second"
    );
}

/// `data`'s doc: "`send` seals and stages a frame from the slot it names." With the 65,536 slots one `sources` call admits, every staged frame names the slot that holds its fragment.
#[test]
fn every_staged_frame_names_its_fragments_slot_at_the_largest_source_count() {
    let count: u32 = 1 << 16;
    let shared = arena_sized(count, 8192);
    let mut budget = EngineBudget::new(1 << 30);
    let slots = sources(&shared, count, &mut budget).unwrap();
    assert_eq!(slots.len(), count as usize, "premise: every slot is held");
    let releases = Releases::new(4, &mut budget).unwrap();
    let mut requests =
        ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let config = UploadConfig {
        retry_us: 1_000,
        attempts: 3,
    };
    let mut core = UploadCore::new(config, slots, &mut requests, &mut budget).unwrap();
    let body = count * 8192;
    let id = core
        .put(
            &mut requests,
            SESSION,
            key(6),
            CacheVersion(0),
            0,
            1_000_000,
        )
        .unwrap();
    sent(&mut core, &mut requests, 0);
    let wire = requests.upload(id).unwrap().wire();
    let authority = Header {
        allocation: 5,
        ..header(Kind::PutAuthority, wire, key(6))
    };
    assert!(core.receive(&mut requests, SESSION, &authority, 0));
    core.prepare(&mut requests, id, 0, body, TTL_MS).unwrap();
    sent(&mut core, &mut requests, 0);
    let ready = Header {
        allocation: 5,
        grant: count,
        ..manifest_reply(Kind::PutReady, wire, key(6), body)
    };
    assert!(core.receive(&mut requests, SESSION, &ready, 0));
    // Each fragment's bytes begin with its index, so no two fragments share a crc by content.
    let mut piece = payload(8192, 41);
    for index in 0..count {
        piece[..4].copy_from_slice(&index.to_le_bytes());
        assert_eq!(core.supply(&mut requests, id, index, &piece), Ok(8192));
    }
    let mut named = Vec::new();
    let staged = core.data(&mut requests, count as usize, |_, header, slot, source| {
        named.push((header.index, slot, source.crc()));
        true
    });
    assert_eq!(staged, count as usize, "premise: every fragment staged");
    let misnamed: Vec<(u32, u16)> = named
        .into_iter()
        .filter(|&(_, slot, crc)| core.slots()[usize::from(slot)].crc() != crc)
        .map(|(index, slot, _)| (index, slot))
        .collect();
    assert_eq!(
        misnamed,
        [],
        "frames whose named slot holds another fragment"
    );
}

/// [`UploadCore::new`] refuses more source slots than the 65,536 a staged frame's `u16` slot index names, as two `sources` results joined supply, and leaves `budget` and `requests` unchanged on the refusal: a core of 65,536 slots from the same arena builds next, and every staged frame names its fragment's slot (the test above).
#[test]
fn an_upload_core_refuses_more_source_slots_than_a_frame_s_slot_index_names() {
    let shared = arena_sized((1 << 16) + 1, 8192);
    let mut budget = EngineBudget::new(1 << 30);
    let mut slots = sources(&shared, 1 << 16, &mut budget).unwrap().into_vec();
    slots.extend(sources(&shared, 1, &mut budget).unwrap().into_vec());
    let releases = Releases::new(4, &mut budget).unwrap();
    let mut requests =
        ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let config = UploadConfig {
        retry_us: 1_000,
        attempts: 3,
    };
    let before = budget;
    let refused = UploadCore::new(config, slots.into_boxed_slice(), &mut requests, &mut budget);
    assert!(
        matches!(refused, Err(FetchCoreError::Sources { count: 65_537 })),
        "a core whose frame would name source slot 65,536 as slot 0 was built"
    );
    assert_eq!(budget, before, "the refusal charged the budget");
    let largest = sources(&shared, 1 << 16, &mut budget).unwrap();
    assert!(
        UploadCore::new(config, largest, &mut requests, &mut budget).is_ok(),
        "the refusal left the requests serving an upload core, or kept the slots' buffers"
    );
}
