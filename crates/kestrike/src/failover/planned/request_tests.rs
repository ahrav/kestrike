use std::cell::Cell;

use super::*;
use crate::failover::sim::host;
use crate::isa_witness::{Kernel, detected, runs, witness};
use crate::storage::session_at;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Plant {
    FieldsFirst,
    AttemptsIgnored,
}

thread_local! {
    static PLANTED: Cell<Option<Plant>> = const { Cell::new(None) };
}

pub(super) fn planted(plant: Plant) -> bool {
    PLANTED.with(Cell::get) == Some(plant)
}

fn with_plant<T>(plant: Plant, f: impl FnOnce() -> T) -> T {
    PLANTED.with(|cell| cell.set(Some(plant)));
    let out = f();
    PLANTED.with(|cell| cell.set(None));
    out
}

const TRANSFER: &[u8; REQUEST_LEN] = include_bytes!("../fixtures/planned-transfer-v1.req");
const RESTART: &[u8; REQUEST_LEN] = include_bytes!("../fixtures/planned-restart-v1.req");

fn key() -> RequestKey {
    RequestKey::derive(&[0x42; 32])
}

fn operation(first: u8) -> ExitOperation {
    ExitOperation::new(std::array::from_fn(|at| first + at as u8)).unwrap()
}

fn transfer() -> PlannedRequest {
    PlannedRequest {
        kind: Kind::Transfer { target: host(12) },
        operation: operation(1),
        sequence: Sequence::of(1_800_000_000, 7),
        shard: Shard::new(3).unwrap(),
        generation: ShardGeneration::new(5).unwrap(),
        attempts: 9,
        owner: host(11),
        deadline_us: NonZeroU32::new(30_000_000).unwrap(),
    }
}

fn restart() -> PlannedRequest {
    PlannedRequest {
        kind: Kind::Restart,
        operation: operation(17),
        sequence: Sequence::of(1_800_000_000, 8),
        ..transfer()
    }
}

fn sealed(body: &[u8], key: &RequestKey, addressed: Host) -> Vec<u8> {
    let (body, _) = body.split_first_chunk().unwrap();
    let mut bytes = body.to_vec();
    bytes.extend(tag(key, addressed, body));
    bytes
}

fn edited(request: &PlannedRequest, edits: &[(usize, &[u8])]) -> Vec<u8> {
    let mut body = encode(request, &key()).to_vec();
    for (at, value) in edits {
        put(&mut body, *at, value);
    }
    body
}

fn flipped(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes[REQUEST_LEN - 1] ^= 1;
    bytes
}

const G: u64 = 5;
const E: u32 = 9;

fn tenure() -> Session {
    session_at(G, E - 1)
}

fn bound(request: PlannedRequest, session: &Session) -> PlannedRequest {
    let own = session.target();
    PlannedRequest {
        shard: session.shard(),
        generation: own.generation,
        attempts: own.attempts,
        owner: own.owner,
        ..request
    }
}

fn authenticated(request: PlannedRequest) -> AuthenticatedRequest {
    decode(&encode(&request, &key()), request.owner, &key()).unwrap()
}

fn at(request: PlannedRequest, counter: u32) -> PlannedRequest {
    PlannedRequest {
        sequence: Sequence::of(1_800_000_000, counter),
        ..request
    }
}

const STATES: [State; 5] = [
    State::PreBoundary,
    State::Recovering,
    State::Serving,
    State::Withdrawn,
    State::Closed,
];

fn decoded(bytes: &[u8], addressed: Host) -> Result<PlannedRequest, RequestError> {
    decode(bytes, addressed, &key()).map(|request| *request.request())
}

#[test]
fn a_request_round_trips_through_its_pinned_encoding() {
    for (request, fixture) in [(transfer(), TRANSFER), (restart(), RESTART)] {
        let bytes = encode(&request, &key());
        assert_eq!(bytes.as_slice(), fixture, "{:?}", request.kind);
        assert_eq!(decoded(fixture, request.owner), Ok(request));
    }
}

/// The tag under a derived key equals RFC 2104's HMAC-SHA256, computed by `assignment::hmac` under the derived key
/// bytes, over the domain label, the addressed host and the body, under 256 host keys. Each key's host holds eight
/// distinct bytes that change with the key, and its three bodies are one whose bytes change with the key and the
/// two pinned bodies. The portable compression gives the same tag from the same blocks. Where the build holds the
/// one-chain kernel and the CPU has `sha2` and `sha3`, the kernel computes every tag inside its witness, twice a
/// tag: 768 tags run it 1,536 times, and a tag that took the other path would lower the count. Every other build
/// and CPU runs it zero times.
#[test]
fn a_tag_equals_hmac_sha256_under_the_derived_key_bytes() {
    let before = runs(Kernel::Sha2One);
    let mut detected = detected!(aarch64: "sha2", "sha3");
    detected.present &= cfg!(all(target_endian = "little", not(miri)));
    let kernel = detected.present;
    witness(
        "sha2-one-request",
        detected,
        || runs(Kernel::Sha2One),
        || {
            for seed in 0..=u8::MAX {
                let host_key =
                    std::array::from_fn(|at| seed.wrapping_mul(31).wrapping_add(at as u8));
                let raw = hmac(&host_key, &[KEY_DOMAIN]);
                let derived = RequestKey::derive(&host_key);
                let octets = std::array::from_fn(|at| seed.wrapping_add(17 * at as u8));
                let addressed = Host::new(u64::from_be_bytes(octets)).unwrap();
                let seeded: [u8; TAG_AT] =
                    std::array::from_fn(|at| seed ^ (at as u8).wrapping_mul(7));
                let pinned = [TRANSFER, RESTART].map(|fixture| *fixture.first_chunk().unwrap());
                for body in [seeded, pinned[0], pinned[1]] {
                    let expected = hmac(&raw, &[DOMAIN, &octets, &body]);
                    assert_eq!(tag(&derived, addressed, &body), expected, "seed {seed}");
                    let portable = chained(&derived, &sealed_blocks(addressed, &body), compress256);
                    assert_eq!(portable, expected, "seed {seed}, the portable compression");
                }
            }
        },
    );
    let ran = runs(Kernel::Sha2One) - before;
    assert_eq!(ran, if kernel { 1_536 } else { 0 }, "kernel runs");
}

/// A body and a derived key of one repeated byte, 0x00, 0x80 (the padding byte's value) and 0xff, under a host
/// that repeats that byte with its low bit set, still match the reference, so the padding byte and the length
/// field stand apart from the message bytes.
#[test]
fn a_tag_over_uniform_bytes_equals_hmac_sha256() {
    for byte in [0x00, 0x80, 0xff] {
        let raw = [byte; 32];
        let key = RequestKey(keyed(&raw));
        let addressed = Host::new(u64::from_be_bytes([byte | 1; 8])).unwrap();
        let body = [byte; TAG_AT];
        let expected = hmac(&raw, &[DOMAIN, &addressed.get().to_be_bytes(), &body]);
        assert_eq!(tag(&key, addressed, &body), expected, "byte {byte:#x}");
    }
}

#[test]
fn every_field_byte_lands_at_its_offset() {
    let request = PlannedRequest {
        kind: Kind::Transfer {
            target: host(0x3132_3334_3536_3738),
        },
        operation: operation(0x61),
        sequence: Sequence(0x5152_5354_5556_5758),
        shard: Shard::new(0x0102_0304).unwrap(),
        generation: ShardGeneration::new(0x0A0B_0C0D).unwrap(),
        attempts: 0x1112_1314,
        owner: host(0x2122_2324_2526_2728),
        deadline_us: NonZeroU32::new(0x4142_4344).unwrap(),
    };
    let bytes = encode(&request, &key());
    let sealed = tag(&key(), request.owner, bytes.split_first_chunk().unwrap().0);
    let fields: [(usize, &[u8]); 11] = [
        (0, &[0, 1]),
        (KIND_AT, &[1]),
        (
            OPERATION_AT,
            &[
                0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
                0x6F, 0x70,
            ],
        ),
        (
            SEQUENCE_AT,
            &[0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58],
        ),
        (SHARD_AT, &[1, 2, 3, 4]),
        (GENERATION_AT, &[0, 0, 0, 0, 0x0A, 0x0B, 0x0C, 0x0D]),
        (ATTEMPTS_AT, &[0x11, 0x12, 0x13, 0x14]),
        (OWNER_AT, &[0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28]),
        (TARGET_AT, &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]),
        (DEADLINE_AT, &[0x41, 0x42, 0x43, 0x44]),
        (TAG_AT, &sealed),
    ];
    for (offset, expected) in fields {
        assert_eq!(
            &bytes[offset..offset + expected.len()],
            expected,
            "at {offset}"
        );
    }
    assert_eq!(decoded(&bytes, request.owner), Ok(request));
}

type Forged = (String, Vec<u8>, Host, RequestError);

fn forged() -> Vec<Forged> {
    let request = transfer();
    let owner = request.owner;
    let other_key = RequestKey::derive(&[0x43; 32]);
    let unknown_schema = edited(&request, &[(0, &[0, 9])]);
    let unknown_kind = edited(&request, &[(KIND_AT, &[3])]);
    let zero_shard = edited(&request, &[(SHARD_AT, &[0; 4])]);
    let mut long = sealed(&unknown_schema, &key(), owner);
    long.push(0);
    let short = sealed(&unknown_schema, &key(), owner)[..REQUEST_LEN - 1].to_vec();
    let mut cases = vec![
        ("an empty request", Vec::new(), owner, RequestError::Length),
        (
            "a body one byte short",
            unknown_schema[..TAG_AT - 1].to_vec(),
            owner,
            RequestError::Length,
        ),
        (
            "a body with no tag",
            unknown_schema[..TAG_AT].to_vec(),
            owner,
            RequestError::Length,
        ),
        (
            "a flipped tag byte",
            flipped(sealed(&unknown_schema, &key(), owner)),
            owner,
            RequestError::Tag,
        ),
        (
            "another host's key",
            sealed(&unknown_schema, &other_key, owner),
            owner,
            RequestError::Tag,
        ),
        (
            "sealed for another host",
            sealed(&unknown_schema, &key(), host(12)),
            owner,
            RequestError::Tag,
        ),
        (
            "decoded at another host",
            sealed(&unknown_schema, &key(), owner),
            host(12),
            RequestError::Tag,
        ),
        (
            "an unknown kind under a flipped tag",
            flipped(sealed(&unknown_kind, &key(), owner)),
            owner,
            RequestError::Tag,
        ),
        (
            "a zero shard under a flipped tag",
            flipped(sealed(&zero_shard, &key(), owner)),
            owner,
            RequestError::Tag,
        ),
        ("a long body", long, owner, RequestError::Length),
        ("a short body", short, owner, RequestError::Length),
    ]
    .into_iter()
    .map(|(name, bytes, addressed, error)| (name.to_string(), bytes, addressed, error))
    .collect::<Vec<_>>();
    for (fixture, bytes) in [("transfer", TRANSFER), ("restart", RESTART)] {
        for (case, forged, addressed) in [
            ("a flipped tag byte", flipped(bytes.to_vec()), owner),
            (
                "another host's key",
                sealed(bytes, &other_key, owner),
                owner,
            ),
            ("decoded at another host", bytes.to_vec(), host(12)),
        ] {
            let name = format!("the {fixture} fixture with {case}");
            cases.push((name, forged, addressed, RequestError::Tag));
        }
    }
    cases
}

fn forged_failures() -> Vec<String> {
    forged()
        .into_iter()
        .filter_map(|(name, bytes, addressed, expected)| {
            let decoded = decoded(&bytes, addressed);
            (decoded != Err(expected)).then(|| format!("{name}: {decoded:?}"))
        })
        .collect()
}

#[test]
fn a_forged_or_misaddressed_request_refuses_before_any_field_is_read() {
    assert_eq!(forged_failures(), Vec::<String>::new());
}

#[test]
fn control_a_decoder_reading_fields_before_the_tag_fails_the_forged_cases() {
    let failures = with_plant(Plant::FieldsFirst, forged_failures);
    let expected = [
        "a flipped tag byte: Err(Schema)",
        "another host's key: Err(Schema)",
        "sealed for another host: Err(Schema)",
        "decoded at another host: Err(Schema)",
        "an unknown kind under a flipped tag: Err(Kind)",
        "a zero shard under a flipped tag: Err(Field)",
    ];
    assert_eq!(failures, expected, "REQUEST-AUTHENTICATED");
}

#[test]
fn an_authenticated_request_outside_the_encoding_refuses() {
    let request = transfer();
    let past = (u64::from(u32::MAX) + 1).to_be_bytes();
    let wide = 0x0000_0001_0000_0005u64.to_be_bytes();
    let other_owner = 12u64.to_be_bytes();
    let cases = [
        (
            "unknown schema",
            edited(&request, &[(0, &[0, 2])]),
            RequestError::Schema,
        ),
        (
            "schema 0",
            edited(&request, &[(0, &[0, 0])]),
            RequestError::Schema,
        ),
        (
            "unknown kind",
            edited(&request, &[(KIND_AT, &[3])]),
            RequestError::Kind,
        ),
        (
            "unknown kind with a zero target",
            edited(&restart(), &[(KIND_AT, &[3])]),
            RequestError::Kind,
        ),
        (
            "kind 0 with a target",
            edited(&request, &[(KIND_AT, &[0])]),
            RequestError::Kind,
        ),
        (
            "kind 0 with a zero target",
            edited(&restart(), &[(KIND_AT, &[0])]),
            RequestError::Kind,
        ),
        (
            "zero target",
            edited(&request, &[(TARGET_AT, &[0; 8])]),
            RequestError::Kind,
        ),
        (
            "restart target",
            edited(&restart(), &[(TARGET_AT, &12u64.to_be_bytes())]),
            RequestError::Kind,
        ),
        (
            "zero operation",
            edited(&request, &[(OPERATION_AT, &[0; 16])]),
            RequestError::Field,
        ),
        (
            "zero shard",
            edited(&request, &[(SHARD_AT, &[0; 4])]),
            RequestError::Field,
        ),
        (
            "zero generation",
            edited(&request, &[(GENERATION_AT, &[0; 8])]),
            RequestError::Field,
        ),
        (
            "generation range",
            edited(&request, &[(GENERATION_AT, &past)]),
            RequestError::Field,
        ),
        (
            "generation range with a valid low word",
            edited(&request, &[(GENERATION_AT, &wide)]),
            RequestError::Field,
        ),
        (
            "zero owner",
            edited(&request, &[(OWNER_AT, &[0; 8])]),
            RequestError::Field,
        ),
        (
            "transfer owner other than the addressee",
            edited(&request, &[(OWNER_AT, &other_owner)]),
            RequestError::Addressee,
        ),
        (
            "restart owner other than the addressee",
            edited(&restart(), &[(OWNER_AT, &other_owner)]),
            RequestError::Addressee,
        ),
        (
            "zero deadline",
            edited(&request, &[(DEADLINE_AT, &[0; 4])]),
            RequestError::Field,
        ),
        (
            "unknown schema and unknown kind",
            edited(&request, &[(0, &[0, 2]), (KIND_AT, &[3])]),
            RequestError::Schema,
        ),
        (
            "unknown kind and zero shard",
            edited(&request, &[(KIND_AT, &[3]), (SHARD_AT, &[0; 4])]),
            RequestError::Kind,
        ),
    ];
    for (name, body, expected) in cases {
        let bytes = sealed(&body, &key(), request.owner);
        assert_eq!(decoded(&bytes, request.owner), Err(expected), "{name}");
        let forged = flipped(bytes);
        assert_eq!(
            decoded(&forged, request.owner),
            Err(RequestError::Tag),
            "{name} under a flipped tag"
        );
    }
}

#[test]
fn a_request_for_the_serving_tenure_is_accepted() {
    let session = tenure();
    for request in [transfer(), restart()] {
        let mut ledger = Ledger::new(&session);
        let binding = ledger.admit(&authenticated(bound(request, &session)), State::Serving);
        assert_eq!(binding, Binding::Accept);
        assert_eq!(ledger.running(), Some(request.operation));
    }
}

fn later_tenures() -> [(&'static str, Session); 3] {
    [
        ("a later E", session_at(G, E)),
        ("a later generation", session_at(G + 1, E - 1)),
        ("a later generation at a lower E", session_at(G + 1, E - 6)),
    ]
}

fn stale_failures() -> Vec<String> {
    let request = bound(transfer(), &tenure());
    later_tenures()
        .into_iter()
        .filter_map(|(name, session)| {
            let mut ledger = Ledger::new(&session);
            let empty = ledger.clone();
            let binding = ledger.admit(&authenticated(request), State::Serving);
            (binding != Binding::Stale || ledger != empty).then(|| format!("{name}: {binding:?}"))
        })
        .collect()
}

#[test]
fn a_request_for_an_earlier_tenure_of_this_owner_is_stale() {
    assert_eq!(stale_failures(), Vec::<String>::new());
}

#[test]
fn control_a_binding_check_ignoring_e_fails_the_stale_cases() {
    let failures = with_plant(Plant::AttemptsIgnored, stale_failures);
    assert_eq!(failures, ["a later E: Accept"], "ONE-TENURE");
}

fn not_owner_requests() -> Vec<PlannedRequest> {
    let request = bound(transfer(), &tenure());
    let earlier = ShardGeneration::new(G - 1).unwrap();
    let later = ShardGeneration::new(G + 1).unwrap();
    vec![
        PlannedRequest {
            generation: later,
            ..request
        },
        PlannedRequest {
            attempts: E + 1,
            ..request
        },
        PlannedRequest {
            generation: later,
            attempts: E - 7,
            ..request
        },
        PlannedRequest {
            owner: host(12),
            ..request
        },
        PlannedRequest {
            owner: host(12),
            attempts: E - 1,
            ..request
        },
        PlannedRequest {
            shard: Shard::new(4).unwrap(),
            ..request
        },
        PlannedRequest {
            shard: Shard::new(4).unwrap(),
            generation: earlier,
            ..request
        },
    ]
}

#[test]
fn a_request_naming_another_owner_or_a_later_tenure_is_not_owner() {
    let session = tenure();
    for named in not_owner_requests() {
        let mut ledger = Ledger::new(&session);
        let empty = ledger.clone();
        let binding = ledger.admit(&authenticated(named), State::Serving);
        assert_eq!(binding, Binding::NotOwner, "{named:?}");
        assert_eq!(ledger, empty, "{named:?}");
    }
}

#[test]
fn a_misbound_request_naming_the_running_operation_leaves_the_ledger_as_accepted() {
    let probe = at(bound(transfer(), &tenure()), 30);
    let mut cases: Vec<(Session, PlannedRequest, Binding)> = later_tenures()
        .into_iter()
        .map(|(_, session)| (session, probe, Binding::Stale))
        .collect();
    for named in not_owner_requests() {
        cases.push((tenure(), at(named, 30), Binding::NotOwner));
    }
    for (session, probe, expected) in cases {
        let mut ledger = Ledger::new(&session);
        let seed = at(bound(probe, &session), 1);
        assert_eq!(
            ledger.admit(&authenticated(seed), State::Serving),
            Binding::Accept
        );
        let accepted = ledger.clone();
        let binding = ledger.admit(&authenticated(probe), State::Serving);
        assert_eq!(binding, expected, "{probe:?}");
        assert_eq!(ledger, accepted, "{probe:?}");
    }
}

#[test]
fn a_new_tenure_of_the_host_accepts_nothing_addressed_to_the_old_one() {
    let (old, new) = (tenure(), session_at(G, E));
    let first = bound(transfer(), &old);
    let mut old_ledger = Ledger::new(&old);
    assert_eq!(
        old_ledger.admit(&authenticated(first), State::Serving),
        Binding::Accept
    );
    let accepted = old_ledger.clone();
    let later = at(bound(restart(), &new), 30);
    let binding = old_ledger.admit(&authenticated(later), State::Serving);
    assert_eq!(binding, Binding::NotOwner);
    assert_eq!(old_ledger, accepted);
    let mut new_ledger = Ledger::new(&new);
    let binding = new_ledger.admit(&authenticated(first), State::Serving);
    assert_eq!(binding, Binding::Stale);
    let fresh = at(bound(restart(), &new), 1);
    let binding = new_ledger.admit(&authenticated(fresh), State::Serving);
    assert_eq!(binding, Binding::Accept);
}

#[test]
fn a_second_operation_refuses_busy_and_a_repeat_reads_the_running_one() {
    let session = tenure();
    let first = bound(transfer(), &session);
    let mut ledger = Ledger::new(&session);
    assert_eq!(
        ledger.admit(&authenticated(first), State::Serving),
        Binding::Accept
    );
    let accepted = ledger.clone();
    assert_eq!(
        ledger.admit(&authenticated(first), State::Serving),
        Binding::Repeat
    );
    assert_eq!(
        ledger, accepted,
        "a repeat at its own sequence changes nothing"
    );
    let second = bound(restart(), &session);
    assert_eq!(
        ledger.admit(&authenticated(second), State::Serving),
        Binding::Busy
    );
    assert_eq!(ledger.running(), Some(first.operation));
}

#[test]
fn admission_checks_the_repeat_then_the_sequence_then_the_serving_state() {
    let session = tenure();
    let first = bound(transfer(), &session);
    let other = bound(restart(), &session);
    let mut ledger = Ledger::new(&session);
    assert_eq!(
        ledger.admit(&authenticated(first), State::Serving),
        Binding::Accept
    );
    let accepted = ledger.clone();
    for state in STATES {
        let binding = ledger.admit(&authenticated(first), state);
        assert_eq!(binding, Binding::Repeat, "{state:?}");
        assert_eq!(ledger, accepted, "{state:?}");
        for low in [6, 7] {
            let binding = ledger.admit(&authenticated(at(other, low)), state);
            assert_eq!(binding, Binding::LowSequence, "{state:?} {low}");
            assert_eq!(ledger, accepted, "{state:?} {low}");
        }
    }
    let binding = ledger.admit(&authenticated(at(other, 9)), State::Withdrawn);
    assert_eq!(binding, Binding::NotServing);
    let binding = ledger.admit(&authenticated(at(other, 10)), State::Serving);
    assert_eq!(binding, Binding::Busy);
    assert_eq!(ledger.running(), Some(first.operation));
}

#[test]
fn a_request_outside_serving_refuses_not_serving() {
    let session = tenure();
    let request = bound(transfer(), &session);
    for state in [
        State::PreBoundary,
        State::Recovering,
        State::Withdrawn,
        State::Closed,
    ] {
        let mut ledger = Ledger::new(&session);
        let binding = ledger.admit(&authenticated(request), state);
        assert_eq!(binding, Binding::NotServing, "{state:?}");
        assert_eq!(ledger.running(), None, "{state:?}");
    }
}

#[test]
fn a_sequence_at_or_below_the_high_water_mark_refuses() {
    let session = tenure();
    let first = bound(transfer(), &session);
    let other = bound(restart(), &session);
    let mut ledger = Ledger::new(&session);
    assert_eq!(
        ledger.admit(&authenticated(first), State::Serving),
        Binding::Accept
    );
    ledger.resumed(first.operation);
    assert_eq!(ledger.running(), None);
    for low in [6, 7] {
        let binding = ledger.admit(&authenticated(at(other, low)), State::Serving);
        assert_eq!(binding, Binding::LowSequence, "{low}");
        assert_eq!(ledger.running(), None, "{low}");
    }
    let mut refused = Ledger::new(&session);
    let binding = refused.admit(&authenticated(first), State::Recovering);
    assert_eq!(binding, Binding::NotServing);
    let binding = refused.admit(&authenticated(at(other, 7)), State::Serving);
    assert_eq!(binding, Binding::LowSequence);
    let binding = refused.admit(&authenticated(at(other, 8)), State::Serving);
    assert_eq!(binding, Binding::Accept);
    let binding = ledger.admit(&authenticated(at(other, 8)), State::Serving);
    assert_eq!(binding, Binding::Accept);
}

#[test]
fn a_busy_refusal_raises_the_mark_and_the_mark_never_lowers() {
    let session = tenure();
    let first = bound(transfer(), &session);
    let other = bound(restart(), &session);
    let mut ledger = Ledger::new(&session);
    assert_eq!(
        ledger.admit(&authenticated(first), State::Serving),
        Binding::Accept
    );
    let binding = ledger.admit(&authenticated(at(other, 20)), State::Serving);
    assert_eq!(binding, Binding::Busy);
    ledger.resumed(first.operation);
    for low in [15, 20] {
        let binding = ledger.admit(&authenticated(at(other, low)), State::Serving);
        assert_eq!(binding, Binding::LowSequence, "{low}");
        assert_eq!(ledger.running(), None, "{low}");
    }
    let binding = ledger.admit(&authenticated(at(other, 21)), State::Serving);
    assert_eq!(binding, Binding::Accept);
}

#[test]
fn a_repeat_raises_the_mark_and_an_ended_operation_stays_a_repeat() {
    let session = tenure();
    let first = at(bound(transfer(), &session), 10);
    let other = bound(restart(), &session);
    let mut ledger = Ledger::new(&session);
    assert_eq!(
        ledger.admit(&authenticated(first), State::Serving),
        Binding::Accept
    );
    let binding = ledger.admit(&authenticated(at(first, 12)), State::Serving);
    assert_eq!(binding, Binding::Repeat);
    let running = ledger.clone();
    let binding = ledger.admit(&authenticated(at(first, 9)), State::Serving);
    assert_eq!(
        binding,
        Binding::Repeat,
        "a running operation below the mark"
    );
    assert_eq!(ledger, running);
    ledger.resumed(first.operation);
    let binding = ledger.admit(&authenticated(at(other, 11)), State::Serving);
    assert_eq!(binding, Binding::LowSequence);
    let ended = ledger.clone();
    for state in STATES {
        for counter in [9, 12] {
            let mut probe = ended.clone();
            let binding = probe.admit(&authenticated(at(first, counter)), state);
            assert_eq!(binding, Binding::Repeat, "{state:?} {counter}");
            assert_eq!(probe, ended, "{state:?} {counter}");
        }
    }
    let binding = ledger.admit(&authenticated(at(first, 40)), State::Serving);
    assert_eq!(binding, Binding::Repeat);
    assert_eq!(ledger.running(), None);
    let raised = ledger.clone();
    for low in [39, 40] {
        let binding = ledger.admit(&authenticated(at(other, low)), State::Serving);
        assert_eq!(binding, Binding::LowSequence, "{low}");
        assert_eq!(ledger, raised, "{low}");
    }
    let binding = ledger.admit(&authenticated(at(other, 41)), State::Serving);
    assert_eq!(binding, Binding::Accept);
}

#[test]
fn a_resume_of_another_operation_keeps_the_running_one() {
    let session = tenure();
    let first = bound(transfer(), &session);
    let second = bound(restart(), &session);
    let third = PlannedRequest {
        operation: operation(33),
        ..at(second, 30)
    };
    let mut ledger = Ledger::new(&session);
    assert_eq!(
        ledger.admit(&authenticated(first), State::Serving),
        Binding::Accept
    );
    let accepted = ledger.clone();
    ledger.resumed(second.operation);
    assert_eq!(ledger, accepted);
    ledger.resumed(first.operation);
    assert_eq!(
        ledger.admit(&authenticated(second), State::Serving),
        Binding::Accept
    );
    ledger.resumed(first.operation);
    assert_eq!(ledger.running(), Some(second.operation));
    assert_eq!(
        ledger.admit(&authenticated(third), State::Serving),
        Binding::Busy
    );
    ledger.resumed(second.operation);
    assert_eq!(ledger.running(), None);
}

#[test]
fn a_later_issuer_start_sequences_above_every_earlier_one() {
    for (earlier, later) in [
        (0, 1),
        (1_800_000_000, 1_800_000_001),
        (u32::MAX - 1, u32::MAX),
    ] {
        for (a, b) in [(u32::MAX, 0), (0, 0), (7, 3)] {
            assert!(Sequence::of(later, b) > Sequence::of(earlier, a));
        }
    }
    assert!(Sequence::of(5, 2) > Sequence::of(5, 1));
    assert_eq!(
        Sequence::of(0x0102_0304, 0x8506_0708),
        Sequence(0x0102_0304_8506_0708)
    );
    assert!(Sequence::of(5, 0x0001_0000) > Sequence::of(5, 0xFFFF));
}

#[test]
fn every_changed_byte_of_a_pinned_request_refuses_by_tag() {
    for (request, fixture) in [(transfer(), TRANSFER), (restart(), RESTART)] {
        assert_eq!(decoded(fixture, request.owner), Ok(request));
        for at in 0..REQUEST_LEN {
            let mut bytes = fixture.to_vec();
            bytes[at] ^= 0x80;
            let decoded = decoded(&bytes, request.owner);
            assert_eq!(
                decoded,
                Err(RequestError::Tag),
                "{:?} byte {at}",
                request.kind
            );
        }
    }
}

#[test]
fn one_ledger_orders_requests_across_an_issuer_restart() {
    let session = tenure();
    let earlier = PlannedRequest {
        sequence: Sequence::of(1_800_000_000, 7),
        ..bound(transfer(), &session)
    };
    let later = PlannedRequest {
        sequence: Sequence::of(1_800_000_001, 0),
        ..bound(restart(), &session)
    };
    let delayed = PlannedRequest {
        operation: operation(33),
        sequence: Sequence::of(1_800_000_000, 40),
        ..earlier
    };
    let mut ledger = Ledger::new(&session);
    assert_eq!(
        ledger.admit(&authenticated(earlier), State::Serving),
        Binding::Accept
    );
    ledger.resumed(earlier.operation);
    assert_eq!(
        ledger.admit(&authenticated(later), State::Serving),
        Binding::Accept
    );
    ledger.resumed(later.operation);
    let binding = ledger.admit(&authenticated(delayed), State::Serving);
    assert_eq!(binding, Binding::LowSequence);
    assert_eq!(ledger.running(), None);
}

#[test]
fn an_earlier_operation_of_the_tenure_is_consumed_at_any_sequence() {
    let session = tenure();
    let first = bound(transfer(), &session);
    let second = bound(restart(), &session);
    let mut ledger = Ledger::new(&session);
    assert_eq!(
        ledger.admit(&authenticated(first), State::Serving),
        Binding::Accept
    );
    ledger.resumed(first.operation);
    assert_eq!(
        ledger.admit(&authenticated(second), State::Serving),
        Binding::Accept
    );
    ledger.resumed(second.operation);
    for state in STATES {
        let mut probe = ledger.clone();
        let binding = probe.admit(&authenticated(at(first, 50)), state);
        assert_eq!(binding, Binding::Consumed, "{state:?}");
        assert_eq!(probe.running(), None, "{state:?}");
    }
    let binding = ledger.admit(&authenticated(at(first, 50)), State::Serving);
    assert_eq!(binding, Binding::Consumed);
    let binding = ledger.admit(&authenticated(at(first, 9)), State::Serving);
    assert_eq!(binding, Binding::Consumed, "below the mark of 50");
    let binding = ledger.admit(&authenticated(at(second, 49)), State::Serving);
    assert_eq!(binding, Binding::Repeat);
    let third = PlannedRequest {
        operation: operation(33),
        ..at(first, 51)
    };
    assert_eq!(
        ledger.admit(&authenticated(third), State::Serving),
        Binding::Accept
    );
}

#[test]
fn a_tenure_refuses_operations_past_its_limit() {
    let session = tenure();
    let mut ledger = Ledger::new(&session);
    let request = |n: usize| PlannedRequest {
        operation: ExitOperation::new((n as u128 + 1).to_be_bytes()).unwrap(),
        ..at(bound(transfer(), &session), n as u32 + 1)
    };
    for n in 0..OPERATIONS_MAX {
        let next = request(n);
        assert_eq!(
            ledger.admit(&authenticated(next), State::Serving),
            Binding::Accept,
            "{n}"
        );
        ledger.resumed(next.operation);
    }
    let past = request(OPERATIONS_MAX);
    let mut outside = ledger.clone();
    let binding = outside.admit(&authenticated(past), State::Withdrawn);
    assert_eq!(
        binding,
        Binding::NotServing,
        "a full tenure outside Serving"
    );
    let mut rolling = ledger.clone();
    assert!(rolling.start_roll());
    let binding = rolling.admit(&authenticated(past), State::Serving);
    assert_eq!(binding, Binding::Busy, "a full tenure during a roll");
    let binding = ledger.admit(&authenticated(past), State::Serving);
    assert_eq!(binding, Binding::Full);
    assert_eq!(ledger.running(), None);
    let latest = request(OPERATIONS_MAX - 1);
    let binding = ledger.admit(&authenticated(at(latest, 900)), State::Serving);
    assert_eq!(binding, Binding::Repeat);
}

#[test]
fn a_request_while_a_roll_runs_refuses_busy_and_raises_the_mark() {
    let session = tenure();
    let first = bound(transfer(), &session);
    let other = bound(restart(), &session);
    let mut ledger = Ledger::new(&session);
    assert_eq!(
        ledger.admit(&authenticated(first), State::Serving),
        Binding::Accept
    );
    assert!(
        !ledger.start_roll(),
        "a roll waits for the running operation"
    );
    let binding = ledger.admit(&authenticated(at(first, 8)), State::Serving);
    assert_eq!(binding, Binding::Repeat);
    ledger.resumed(first.operation);
    assert!(ledger.start_roll());
    assert!(!ledger.start_roll(), "one roll at a time");
    let binding = ledger.admit(&authenticated(at(other, 20)), State::Serving);
    assert_eq!(binding, Binding::Busy);
    assert_eq!(ledger.running(), None);
    let binding = ledger.admit(&authenticated(at(first, 21)), State::Serving);
    assert_eq!(
        binding,
        Binding::Repeat,
        "the roll is not the latest requested operation"
    );
    ledger.roll_resumed();
    let binding = ledger.admit(&authenticated(at(other, 15)), State::Serving);
    assert_eq!(binding, Binding::LowSequence);
    let binding = ledger.admit(&authenticated(at(other, 22)), State::Serving);
    assert_eq!(binding, Binding::Accept);
}
