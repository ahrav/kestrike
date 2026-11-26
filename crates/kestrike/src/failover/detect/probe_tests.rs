use super::*;
use crate::failover::detect::beat::BeatKey;
use crate::failover::report::ReportKey;
use crate::failover::sim::host;

fn key_of(h: Host) -> ProbeKey {
    ProbeKey::derive(&[h.get() as u8; 32])
}

fn keys(h: Host) -> Option<ProbeKey> {
    Some(key_of(h))
}

/// A request with every field at its lowest value and one with every field at its highest.
fn bounds() -> [ProbeRequest; 2] {
    [
        ProbeRequest {
            suspect: host(1),
            partition: Partition(0),
            generation: ObservationGeneration(0),
            cycle: 0,
            round: 0,
            issued: 0,
        },
        ProbeRequest {
            suspect: host(u64::MAX),
            partition: Partition(u32::MAX),
            generation: ObservationGeneration(u64::MAX),
            cycle: u64::MAX,
            round: u32::MAX,
            issued: u64::MAX,
        },
    ]
}

fn messages() -> Vec<Message> {
    let readings = [
        Reading::Alive,
        Reading::Dead(Failure::Silent),
        Reading::Dead(Failure::Gray),
        Reading::Unknown,
        Reading::Dead(Failure::Declared),
    ];
    (bounds().into_iter())
        .flat_map(|request| {
            let replies = readings.map(|reading| Message::Reply { request, reading });
            std::iter::once(Message::Request(request)).chain(replies)
        })
        .collect()
}

/// `bytes` with its tag recomputed for `receiver` under `sender`'s key, so a check after the tag sees the change.
fn resealed(mut bytes: [u8; LEN], sender: Host, receiver: Host) -> [u8; LEN] {
    let key = key_of(sender);
    let body = &bytes[..TAG_AT];
    let tag = hmac(&key.0, &[DOMAIN, &receiver.get().to_be_bytes(), body]);
    bytes[TAG_AT..].copy_from_slice(&tag);
    bytes
}

#[test]
fn every_message_at_its_field_bounds_round_trips_to_its_bytes() {
    for sender in [host(1), host(u64::MAX)] {
        for message in messages() {
            for boot in [[0; 16], [0xFF; 16]] {
                let bytes = encode(&message, boot, sender, host(9), &key_of(sender));
                let decoded = decode(&bytes, host(9), keys).unwrap();
                assert_eq!(decoded, (sender, boot, message));
                let again = encode(&decoded.2, decoded.1, sender, host(9), &key_of(sender));
                assert_eq!(again, bytes);
            }
        }
    }
}

#[test]
fn the_probe_codec_matches_its_layout() {
    let request = ProbeRequest {
        suspect: host(0x1112_1314_1516_1718),
        partition: Partition(0x2122_2324),
        generation: ObservationGeneration(0x3132_3334_3536_3738),
        cycle: 0x4142_4344_4546_4748,
        round: 0x5152_5354,
        issued: 0x6162_6364_6566_6768,
    };
    let reply = Message::Reply {
        request,
        reading: Reading::Dead(Failure::Gray),
    };
    let boot: [u8; 16] = core::array::from_fn(|at| 0x71 + at as u8);
    let bytes = encode(
        &reply,
        boot,
        host(0x0102_0304_0506_0708),
        host(9),
        &key_of(host(8)),
    );
    assert_eq!(bytes.len(), LEN);
    assert_eq!(bytes[..4], [0, 1, 2, 3]);
    assert_eq!(bytes[4..12], 0x0102_0304_0506_0708_u64.to_be_bytes());
    assert_eq!(bytes[12..28], boot);
    assert_eq!(bytes[28..36], 0x1112_1314_1516_1718_u64.to_be_bytes());
    assert_eq!(bytes[36..40], 0x2122_2324_u32.to_be_bytes());
    assert_eq!(bytes[40..48], 0x3132_3334_3536_3738_u64.to_be_bytes());
    assert_eq!(bytes[48..56], 0x4142_4344_4546_4748_u64.to_be_bytes());
    assert_eq!(bytes[56..60], 0x5152_5354_u32.to_be_bytes());
    assert_eq!(bytes[60..68], 0x6162_6364_6566_6768_u64.to_be_bytes());
    for (at, reading) in READINGS.into_iter().enumerate() {
        let coded = encode(
            &Message::Reply { request, reading },
            boot,
            host(8),
            host(9),
            &key_of(host(8)),
        );
        assert_eq!(coded[3], [1, 2, 3, 4, 5][at], "{reading:?}");
    }
    assert_eq!(
        READINGS,
        [
            Reading::Alive,
            Reading::Dead(Failure::Silent),
            Reading::Dead(Failure::Gray),
            Reading::Unknown,
            Reading::Dead(Failure::Declared)
        ]
    );
    let request_bytes = encode(
        &Message::Request(request),
        [9; 16],
        host(8),
        host(9),
        &key_of(host(8)),
    );
    assert_eq!(
        request_bytes[2..4],
        [1, 0],
        "a request is kind 1 with reading 0"
    );
    let tag: String = bytes[TAG_AT..].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        tag, "456f785a6a227cccb34306d5da5f0b8a3317fe271cfa8f3852a996bcde51f337",
        "the tag's domain, key derivation and receiver input are fixed at this version"
    );
}

#[test]
fn a_short_long_or_wrong_version_message_returns_a_typed_refusal() {
    for message in messages() {
        let bytes = encode(&message, [9; 16], host(8), host(9), &key_of(host(8)));
        assert_eq!(
            decode(&bytes[..LEN - 1], host(9), keys),
            Err(ProbeError::Length)
        );
        let mut long = bytes.to_vec();
        long.push(0);
        assert_eq!(decode(&long, host(9), keys), Err(ProbeError::Length));
        for version in [0, VERSION + 1, u16::MAX] {
            let mut wrong = bytes;
            wrong[..2].copy_from_slice(&version.to_be_bytes());
            let wrong = resealed(wrong, host(8), host(9));
            assert_eq!(decode(&wrong, host(9), keys), Err(ProbeError::Version));
        }
    }
    assert_eq!(decode(&[], host(9), keys), Err(ProbeError::Length));
}

#[test]
fn each_field_outside_its_encoding_returns_its_refusal_in_check_order() {
    let [request, _] = bounds();
    let reply = Message::Reply {
        request,
        reading: Reading::Alive,
    };
    let bytes = encode(&reply, [9; 16], host(8), host(9), &key_of(host(8)));
    let changed = |at: usize, value: u8| {
        let mut bytes = bytes;
        bytes[at] = value;
        resealed(bytes, host(8), host(9))
    };
    for kind in [0, 3, u8::MAX] {
        assert_eq!(
            decode(&changed(KIND_AT, kind), host(9), keys),
            Err(ProbeError::Kind)
        );
    }
    for reading in [0, 6, u8::MAX] {
        assert_eq!(
            decode(&changed(READING_AT, reading), host(9), keys),
            Err(ProbeError::Field),
            "reply reading {reading}"
        );
    }
    let request_bytes = encode(
        &Message::Request(request),
        [9; 16],
        host(8),
        host(9),
        &key_of(host(8)),
    );
    let mut read = request_bytes;
    read[READING_AT] = 1;
    let read = resealed(read, host(8), host(9));
    assert_eq!(decode(&read, host(9), keys), Err(ProbeError::Field));
    let mut unnamed = bytes;
    unnamed[SUSPECT_AT..PARTITION_AT].fill(0);
    let unnamed = resealed(unnamed, host(8), host(9));
    assert_eq!(decode(&unnamed, host(9), keys), Err(ProbeError::Field));
    let mut anonymous = bytes;
    anonymous[SENDER_AT..SUSPECT_AT].fill(0);
    assert_eq!(decode(&anonymous, host(9), keys), Err(ProbeError::Sender));
    assert_eq!(decode(&bytes, host(9), |_| None), Err(ProbeError::Sender));
    let mut unsealed = bytes;
    unsealed[READING_AT] = 9;
    assert_eq!(
        decode(&unsealed, host(9), keys),
        Err(ProbeError::Tag),
        "the tag verifies before the reading is read"
    );
    let mut unsealed = bytes;
    unsealed[KIND_AT] = 9;
    assert_eq!(
        decode(&unsealed, host(9), keys),
        Err(ProbeError::Kind),
        "the kind is read before the tag"
    );
    let mut flipped = bytes;
    flipped[LEN - 1] ^= 1;
    assert_eq!(decode(&flipped, host(9), keys), Err(ProbeError::Tag));
    let mut body = bytes;
    body[ISSUED_AT] ^= 1;
    assert_eq!(decode(&body, host(9), keys), Err(ProbeError::Tag));
    assert_eq!(
        decode(&bytes, host(10), keys),
        Err(ProbeError::Tag),
        "a message sealed for host 9 fails at host 10"
    );
    assert_eq!(
        decode(&bytes, host(9), |_| Some(key_of(host(7)))),
        Err(ProbeError::Tag),
        "another host's key"
    );
}

#[test]
fn the_probe_key_is_apart_from_the_heartbeat_and_report_keys_of_one_host_key() {
    let host_key = [0x5A; 32];
    let probe = ProbeKey::derive(&host_key).0;
    assert_ne!(probe, BeatKey::derive(&host_key).0);
    assert_ne!(probe, ReportKey::derive(&host_key).0);
    assert_ne!(probe, host_key);
    assert_ne!(probe, ProbeKey::derive(&[0x5B; 32]).0);
    let hex: String = probe.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex, "a14599263f7768b052732c29ae151b1f4aafc04032f363d1dcdb8f5da999181e",
        "HMAC-SHA256 of the host key over the probe key label"
    );
}

/// The three-compression tag is HMAC-SHA256 (RFC 2104) under the key over the label, the receiver and the body:
/// the value the generic `hmac` returns for those parts. The cases are the all-zero and the all-one body and 200
/// bodies an xorshift generator draws, each under a drawn key and receiver, then one body under the all-zero and
/// the all-one key for two receivers that differ in their lowest bit.
#[test]
fn the_tag_is_hmac_sha256_over_the_label_the_receiver_and_the_body() {
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut bodies = vec![[0; TAG_AT], [0xFF; TAG_AT]];
    bodies.extend((0..200).map(|_| std::array::from_fn(|_| next() as u8)));
    for body in bodies {
        let key = ProbeKey(std::array::from_fn(|_| next() as u8));
        let receiver = Host::new(next()).expect("an xorshift state stays nonzero");
        let expected = hmac(&key.0, &[DOMAIN, &receiver.get().to_be_bytes(), &body]);
        assert_eq!(tag(&key.keyed(), receiver, &body), expected);
    }
    for key in [ProbeKey([0; 32]), ProbeKey([0xFF; 32])] {
        let body = [0x5A; TAG_AT];
        for receiver in [host(u64::MAX - 1), host(u64::MAX)] {
            let expected = hmac(&key.0, &[DOMAIN, &receiver.get().to_be_bytes(), &body]);
            assert_eq!(tag(&key.keyed(), receiver, &body), expected);
        }
    }
}

/// A message sealed under a prepared key carries the tag the generic `hmac` gives its body, and the prepared key
/// opens a message tagged that way to the sender, the boot nonce and the message. Another host's prepared key
/// refuses it by its tag.
#[test]
fn the_prepared_key_seals_the_generic_tag_and_opens_a_message_tagged_with_it() {
    for message in messages() {
        let (sender, receiver) = (host(3), host(9));
        let prepared = key_of(sender).keyed();
        let sealed = seal(&message, [7; 16], sender, receiver, &prepared);
        let tagged = resealed(sealed, sender, receiver);
        assert_eq!(sealed, tagged);
        let opened = open(&tagged, receiver, |_| Some(prepared));
        assert_eq!(opened, Ok((sender, [7; 16], message)));
        let other = key_of(host(4)).keyed();
        assert_eq!(
            open(&tagged, receiver, |_| Some(other)),
            Err(ProbeError::Tag)
        );
    }
}
